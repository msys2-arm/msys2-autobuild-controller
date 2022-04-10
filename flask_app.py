
# A very simple Flask Hello World app for you to get started with...

import functools
import hmac
import requests
import secrets

from contextlib import contextmanager

from cryptography.fernet import Fernet
from flask import Flask, request, abort, session, url_for, redirect, flash
from github import Github


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

oauthapp = Github().get_oauth_application(app.config["GITHUB_CLIENT_ID"], app.config["GITHUB_CLIENT_SECRET"])

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

def github_oauth_state_check(func):
    @functools.wraps(func)
    def wrapper_github_oauth_state_check(*args, **kwargs):
        if 'auth_state' in session:
            if not secrets.compare_digest(session['auth_state'], request.args['state']):
                return abort(401, 'Bad CSRF token')
        return func(*args, **kwargs)
    return wrapper_github_oauth_state_check


@app.route('/')
def index():
    if 'user_id' in session:
        return f'Hello {session["user_type"]}:{session["user_login"]}!'
    return 'Hello from Flask!'

@app.route("/github-webhook", methods=['POST'])
@verify_github_webhook_signature
def github_webhook():
    return "Got it"

def handle_login(next=None):
    session['auth_state'] = secrets.token_urlsafe()
    if next:
        session['auth_next'] = next
    return redirect(oauthapp.get_login_url(state=session['auth_state']))

@app.route('/login')
def login():
    if session.get('user_id', None) is not None:
        flash("Already logged in!")
        return redirect(request.args.get('next') or url_for('index'))
    else:
        return handle_login(request.args.get('next'))

@app.route('/logout')
def logout():
    next_url = request.args.get('next') or url_for('index')
    if 'user_access_token' in session:
        access_token=decrypt_protected_var(session['user_access_token'])
        requests.delete(f'https://api.github.com/applications/{app.config["GITHUB_CLIENT_ID"]}/token',
                        data=f'{{"access_token":"{access_token}"}}',
                        auth=(app.config["GITHUB_CLIENT_ID"], app.config["GITHUB_CLIENT_SECRET"]))
    [session.pop(key) for key in list(session.keys()) if key.startswith('user_')]
    return redirect(next_url)

@app.route('/github-callback')
@github_oauth_state_check
def authorized():
    next_url = session.pop('auth_next', None) or url_for('index')

    access_token = oauthapp.get_access_token(request.args['code'], session.get('auth_state'))
    session['user_access_token'] = encrypt_protected_var(access_token.token)

    user = Github(access_token.token).get_user()
    session['user_id'] = user.id
    session['user_type'] = user.type
    session['user_login'] = user.login

    return redirect(next_url)

