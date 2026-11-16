import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from werkzeug.security import generate_password_hash, check_password_hash

from app import create_app


@pytest.fixture
def app(tmp_path):
    app = create_app({'TESTING': True, 'SECRET_KEY': secrets.token_hex(32),
                      'DATABASE': str(tmp_path / 'db.sqlite'), 'LOGIN_LIMIT': 5})
    with sqlite3.connect(app.config['DATABASE']) as db:
        for name in ('student', 'other'):
            db.execute('INSERT INTO users(username,password_hash) VALUES (?,?)',
                       (name, generate_password_hash('Test-password-123!', method='scrypt')))
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def auth(client, user='student'):
    r = client.post('/auth/login', json={'username': user, 'password': 'Test-password-123!'})
    assert r.status_code == 200
    return {'Authorization': 'Bearer ' + r.json['access_token']}


def test_login_and_data(client):
    assert client.get('/api/data', headers=auth(client)).json == {'items': []}


def test_anonymous_denied(client):
    assert client.get('/api/data').status_code == 401
    assert client.post('/api/notes', json={'text': 'x'}).status_code == 401


def test_sqli_does_not_bypass_login(client):
    r = client.post('/auth/login', json={'username': "student' OR 1=1 --", 'password': 'wrong'})
    assert r.status_code == 401
    assert 'access_token' not in r.json


def test_xss_is_escaped(client):
    h = auth(client)
    r = client.post('/api/notes', headers=h, json={'text': '<script>alert(1)</script>'})
    assert r.status_code == 201
    assert r.json['text'] == '&lt;script&gt;alert(1)&lt;/script&gt;'
    assert '<script>' not in client.get('/api/data', headers=h).get_data(as_text=True)


def test_users_are_isolated(client):
    client.post('/api/notes', headers=auth(client), json={'text': 'private'})
    assert client.get('/api/data', headers=auth(client, 'other')).json['items'] == []


@pytest.mark.parametrize('kind', ['expired', 'wrong_signature', 'wrong_audience', 'missing_exp', 'none'])
def test_invalid_tokens(client, app, kind):
    now = datetime.now(timezone.utc)
    claims = {'sub': '1', 'iat': now, 'exp': now + timedelta(minutes=1),
              'iss': 'secure-notes', 'aud': 'secure-notes-api'}
    key, alg = app.config['SECRET_KEY'], 'HS256'
    if kind == 'expired':
        claims['exp'] = now - timedelta(seconds=1)
    elif kind == 'wrong_signature':
        key = secrets.token_hex(32)
    elif kind == 'wrong_audience':
        claims['aud'] = 'other'
    elif kind == 'missing_exp':
        del claims['exp']
    elif kind == 'none':
        key, alg = '', 'none'
    token = jwt.encode(claims, key, algorithm=alg)
    assert client.get('/api/data', headers={'Authorization': 'Bearer ' + token}).status_code == 401


def test_password_hash(app):
    with sqlite3.connect(app.config['DATABASE']) as db:
        value = db.execute('SELECT password_hash FROM users LIMIT 1').fetchone()[0]
    assert value.startswith('scrypt:')
    assert check_password_hash(value, 'Test-password-123!')
    assert value != 'Test-password-123!'


def test_rate_limit(client):
    for _ in range(5):
        assert client.post('/auth/login', json={'username': 'x', 'password': 'x'}).status_code == 401
    assert client.post('/auth/login', json={'username': 'x', 'password': 'x'}).status_code == 429


def test_validation_and_headers(client):
    h = auth(client)
    assert client.post('/api/notes', headers=h, json={'text': ''}).status_code == 400
    assert client.post('/api/notes', headers=h, json={'text': 'a' * 501}).status_code == 400
    assert client.post('/api/notes', headers=h, data='{', content_type='application/json').status_code == 400
    r = client.get('/api/data', headers=h)
    assert r.headers['X-Content-Type-Options'] == 'nosniff'
    assert r.headers['Cache-Control'] == 'no-store'


def test_secret_required():
    with pytest.raises(ValueError):
        create_app({'SECRET_KEY': ''})
