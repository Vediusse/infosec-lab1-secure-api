"""Small protected notes API for the information security lab."""
import html
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get('JWT_SECRET'),
                      DATABASE=os.environ.get('DATABASE', 'instance/notes.sqlite'),
                      MAX_CONTENT_LENGTH=8192, LOGIN_LIMIT=5)
    app.config.update(config or {})
    if not app.config['SECRET_KEY'] or len(app.config['SECRET_KEY']) < 32:
        raise ValueError('JWT_SECRET must contain at least 32 characters')
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    attempts = {}

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop('db', None)
        if connection:
            connection.close()

    with app.app_context():
        db().executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL,
                text TEXT NOT NULL);
        ''')
        db().commit()

    @app.cli.command('seed')
    def seed():
        """Initialize a demo account using a password supplied via environment."""
        password = os.environ.get('DEMO_PASSWORD', '')
        if len(password) < 12:
            raise ValueError('DEMO_PASSWORD must contain at least 12 characters')
        db().execute('INSERT OR IGNORE INTO users(username,password_hash) VALUES (?,?)',
                     ('student', generate_password_hash(password, method='scrypt')))
        db().commit()
        print('Demo account ready: student (password is not logged)')

    def protected(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            header = request.headers.get('Authorization', '')
            if not header.startswith('Bearer '):
                return jsonify(error='authentication_required'), 401
            try:
                claims = jwt.decode(header[7:], app.config['SECRET_KEY'],
                                    algorithms=['HS256'], issuer='secure-notes',
                                    audience='secure-notes-api',
                                    options={'require': ['exp', 'iat', 'sub', 'iss', 'aud']})
                g.user_id = int(claims['sub'])
                if not db().execute('SELECT id FROM users WHERE id=?', (g.user_id,)).fetchone():
                    raise ValueError('Unknown user')
            except (jwt.InvalidTokenError, ValueError, TypeError):
                app.logger.warning('auth_token_rejected')
                return jsonify(error='invalid_token'), 401
            return view(*args, **kwargs)
        return wrapper

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.errorhandler(Exception)
    def error_response(error):
        if isinstance(error, HTTPException):
            return jsonify(error=error.name.lower().replace(' ', '_')), error.code
        app.logger.error('unexpected_request_failure', exc_info=True)
        return jsonify(error='internal_error'), 500

    @app.post('/auth/login')
    def login():
        address = request.remote_addr
        now = time.monotonic()
        # Single-process teaching example: production requires a shared limiter.
        for key in list(attempts):
            if now - attempts[key][0] > 60:
                del attempts[key]
        if len(attempts) >= 10000 and address not in attempts:
            return jsonify(error='try_later'), 429
        start, count = attempts.get(address, (now, 0))
        if count >= app.config['LOGIN_LIMIT']:
            return jsonify(error='rate_limited'), 429
        attempts[address] = (start, count + 1)
        data = request.get_json()
        if not isinstance(data, dict):
            return jsonify(error='invalid_input'), 400
        username, password = data.get('username'), data.get('password')
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 80 or len(password) > 256:
            return jsonify(error='invalid_input'), 400
        user = db().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if user is None or not check_password_hash(user['password_hash'], password):
            app.logger.warning('login_failed')
            return jsonify(error='invalid_credentials'), 401
        issued = datetime.now(timezone.utc)
        token = jwt.encode({'sub': str(user['id']), 'iat': issued,
                            'exp': issued + timedelta(minutes=15),
                            'iss': 'secure-notes', 'aud': 'secure-notes-api'},
                           app.config['SECRET_KEY'], algorithm='HS256')
        app.logger.info('login_succeeded')
        return jsonify({'access_token': token, 'token_type': 'Bearer', 'expires_in': 900})

    @app.get('/api/data')
    @protected
    def data():
        rows = db().execute('SELECT id,text FROM notes WHERE owner_id=? ORDER BY id', (g.user_id,)).fetchall()
        return jsonify(items=[{'id': row['id'], 'text': html.escape(row['text'], quote=True)} for row in rows])

    @app.post('/api/notes')
    @protected
    def create_note():
        data = request.get_json()
        text = data.get('text') if isinstance(data, dict) else None
        if not isinstance(text, str) or not text.strip() or len(text) > 500:
            return jsonify(error='invalid_input'), 400
        cursor = db().execute('INSERT INTO notes(owner_id,text) VALUES (?,?)', (g.user_id, text))
        db().commit()
        return jsonify(id=cursor.lastrowid, text=html.escape(text, quote=True)), 201

    app.logger.setLevel(logging.INFO)
    return app
