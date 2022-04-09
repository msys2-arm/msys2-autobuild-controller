
# A very simple Flask Hello World app for you to get started with...

import functools
import hmac
import secrets

from contextlib import contextmanager

from cryptography.fernet import Fernet
from flask import Flask, request, abort, session, url_for, redirect
from flask_github import GitHub as FlaskGitHub


@contextmanager
def temporary_attribute(obj, attr_name, attr_value):
    old_value = getattr(obj, attr_name)
    setattr(obj, attr_name, attr_value)
    try:
        yield
    finally:
        setattr(obj, attr_name, old_value)

app = Flask(__name__, instance_relative_config=True)
# XXX do I care about default settings?
app.config.from_pyfile('application.cfg', silent=True)

flaskgithub = FlaskGitHub(app)

def encrypt_protected_var(cleartext: str) -> str:
    return Fernet(app.config['FERNET_SECRET_KEY'].encode('utf-8')).encrypt(cleartext.encode('utf-8')).decode('utf-8')

def decrypt_protected_var(ciphertext: str) -> str:
    return Fernet(app.config['FERNET_SECRET_KEY'].encode('utf-8')).decrypt(ciphertext.encode('utf-8')).decode('utf-8')

def verify_github_webhook_signature(func):
    @functools.wraps(func)
    def wrapper_github_webhook_signature_verification(*args, **kwargs):
        signature = "sha256="+hmac.digest(
                app.config['GITHUB_WEBHOOK_SECRET'].encode('utf-8'),
                request.data,
                'SHA256'
            ).hex().lower()
        if not hmac.compare_digest(signature, request.headers['X-Hub-Signature-256']):
            return abort(401, 'Bad digest')
        return func(*args, **kwargs)
    return wrapper_github_webhook_signature_verification


@app.route('/')
def index():
    if 'user_id' in session:
        return f'Hello {session["user_type"]}:{session["user_login"]}!'
    return 'Hello from Flask!'

@app.route("/github-webhook", methods=['POST'])
@verify_github_webhook_signature
def githubWebhook():
    return "Got it"

@app.route('/login')
def login():
    if session.get('user_id', None) is not None:
        return "Already logged in!"
    else:
        session['auth_state'] = secrets.token_urlsafe()
        return flaskgithub.authorize(state=session['auth_state'])

@app.route('/logout')
def logout():
    resp = None
    next_url = request.args.get('next') or url_for('index')
    if 'user_access_token' in session:
        access_token=decrypt_protected_var(session['user_access_token'])
        resp = flaskgithub.session.delete(f'{flaskgithub.BASE_URL}applications/{app.config["GITHUB_CLIENT_ID"]}/token',
                                   data=f'{{"access_token":"{access_token}"}}',
                                   auth=(app.config["GITHUB_CLIENT_ID"], app.config["GITHUB_CLIENT_SECRET"]))
    [session.pop(key) for key in list(session.keys()) if key.startswith('user_')]
    if resp is not None:
        resp.raise_for_status()
    return redirect(next_url)

@app.route('/github-callback')
@flaskgithub.authorized_handler
def authorized(access_token):
    next_url = request.args.get('next') or url_for('index')
    if 'auth_state' in session:
        auth_state = session.pop('auth_state')
        if not secrets.compare_digest(auth_state, request.args['state']):
            return abort(401, 'Bad CSRF token')

    if access_token is None:
        return redirect(next_url)

    session['user_access_token'] = encrypt_protected_var(access_token)

    # TODO use pygithub instead
    with temporary_attribute(flaskgithub, 'get_access_token', lambda *a: access_token):
        github_user = flaskgithub.get('/user')
        session['user_id'] = github_user['id']
        session['user_type'] = github_user['type']
        session['user_login'] = github_user['login']

    return redirect(next_url)

