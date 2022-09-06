
# A very simple Flask Hello World app for you to get started with...

import functools
import hmac
import json
import requests
import secrets
import sys

from contextlib import contextmanager
from typing import Optional

from cryptography.fernet import Fernet
from flask import Flask, request, abort, session, g, url_for, redirect, flash, render_template
import github
from github import Github, GithubIntegration

from validate_autobuild_inputs import validate_optional_deps, validate_clear_failed_build_types, validate_clear_failed_packages
from permissions import Principal, AccessRights


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

with app.open_instance_resource(app.config['GITHUB_APP_KEY_FILE']) as keyfile:
    app.config['GITHUB_APP_KEY'] = keyfile.read()

githubintegration = GithubIntegration(app.config['GITHUB_APP_ID'], app.config['GITHUB_APP_KEY'])
oauthapp = Github().get_oauth_application(app.config["GITHUB_CLIENT_ID"], app.config["GITHUB_CLIENT_SECRET"])

def audit_log(principal, fork, action, params):
    print(f"AUDIT LOG: {principal} {fork} {action} {params!r}", file=sys.stderr)

def encrypt_protected_var(cleartext: str) -> str:
    return Fernet(app.config['FERNET_SECRET_KEY'].encode('utf-8')).encrypt(cleartext.encode('utf-8')).decode('utf-8')

def decrypt_protected_var(ciphertext: str) -> str:
    return Fernet(app.config['FERNET_SECRET_KEY'].encode('utf-8')).decrypt(ciphertext.encode('utf-8')).decode('utf-8')

def _get_autobuild_repo(fork: str, token: Optional[str] = None) -> github.Repository.Repository:
    if token is None:
        installation = githubintegration.get_installation(fork, 'msys2-autobuild')
        installation_token = githubintegration.get_access_token(installation.id)
        token = installation_token.token
    gh = Github(login_or_token=token)
    return gh.get_repo(fork + '/msys2-autobuild', lazy=True)

def clear_login_session():
    [session.pop(key) for key in list(session.keys()) if key.startswith('user_')]

def handle_login(next=None):
    session['auth_state'] = secrets.token_urlsafe()
    if next:
        session['auth_next'] = next
    return redirect(oauthapp.get_login_url(state=session['auth_state']))

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
        if 'auth_state' in session or 'state' in request.args:
            try:
                if not secrets.compare_digest(session['auth_state'], request.args['state']):
                    return abort(401, 'Bad CSRF token')
            except KeyError:
                return abort(401, 'Missing CSRF token')
        return func(*args, **kwargs)
    return wrapper_github_oauth_state_check

def verify_login_token(func):
    @functools.wraps(func)
    def wrapper_verify_login_token(*args, **kwargs):
        resp = None
        if 'user_access_token' in session:
            access_token=decrypt_protected_var(session['user_access_token'])
            resp = requests.post(f'https://api.github.com/applications/{app.config["GITHUB_CLIENT_ID"]}/token',
                                 data=f'{{"access_token":"{access_token}"}}',
                                 auth=(app.config["GITHUB_CLIENT_ID"], app.config["GITHUB_CLIENT_SECRET"]))
        if not resp:
            clear_login_session()
            return handle_login(url_for(request.endpoint, **request.view_args))
        return func(*args, **kwargs)
    return wrapper_verify_login_token

@app.before_request
def load_principal():
    principal = session.get('user_principal')
    if principal:
        g.principal = Principal._make(principal)
    else:
        g.principal = None

@app.route('/', methods=('GET', 'POST'))
def index():
    if not g.principal:
        if request.method != 'GET':
            return abort(405, 'Method not allowed')
        return render_template('index_anonymous.html')
    return authenticated_index()

@verify_login_token
def authenticated_index():
    if 'fork' in request.values and request.values['fork'] in app.config['AUTOBUILD_FORKS']:
        session['fork'] = request.values['fork']
    elif 'fork' not in session:
        session['fork'] = sorted(app.config['AUTOBUILD_FORKS'])[0]

    if request.method == 'POST':
        return redirect(url_for(request.endpoint, **request.view_args))

    # get and use app installation token, or just use user token?
    # as long as we're dealing with public repos, it shouldn't matter
    # so use up the rate limit on the user token instead :)
    repo = _get_autobuild_repo(session['fork'], decrypt_protected_var(session['user_access_token']))
    workflow = github.Workflow.Workflow(repo._requester, {}, {'url': f'{repo.url}/actions/workflows/build.yml'}, completed=False)
    runs = github.PaginatedList.PaginatedList(github.WorkflowRun.WorkflowRun, repo._requester, f'{workflow.url}/runs', {}, list_item="workflow_runs")

    return render_template('index.html', runs=runs, AccessRights=AccessRights)

@app.route('/trigger')
def trigger():
    if not g.principal:
        return handle_login(url_for(request.endpoint, **request.view_args))
    if app.config['ACL'].check(g.principal, AccessRights.TRIGGER_RUN) != AccessRights.TRIGGER_RUN:
        return abort(403, "Access denied")
    return render_template('trigger.html', AccessRights=AccessRights)

@app.route('/maint')
def maint():
    if not g.principal:
        return handle_login(url_for(request.endpoint, **request.view_args))
    if app.config['ACL'].check(g.principal, AccessRights.CLEAR_FAILURES) != AccessRights.CLEAR_FAILURES:
        return abort(403, "Access denied")
    return render_template('maint.html', AccessRights=AccessRights)

@app.route('/verifyauth')
@verify_login_token
def verifyauth():
    return 'Token is good!'

@app.route("/github-webhook", methods=['POST'])
@verify_github_webhook_signature
def github_webhook():
    return "Got it"

def _workflow_dispatch(workflow_yml, inputs):
    repo = _get_autobuild_repo(session['fork'])
    if False:
        workflow = repo.get_workflow(workflow_yml)
    else:
        # don't need to GET the workflow just to trigger it
        workflow = github.Workflow.Workflow(repo._requester, {}, {'url': f'{repo.url}/actions/workflows/{workflow_yml}'}, completed=False)
    return workflow.create_dispatch(repo.default_branch, inputs=inputs)

@app.route("/workflow_dispatch", methods=['POST'])
@verify_login_token
def workflow_dispatch():
    if app.config['ACL'].check(g.principal, AccessRights.TRIGGER_RUN) != AccessRights.TRIGGER_RUN:
        return abort(403, "Access denied")

    inputs = {'context': json.dumps({"principal": str(g.principal)})}
    if request.form.get('optional_deps'):
        if app.config['ACL'].check(g.principal, AccessRights.BREAK_CYCLES) != AccessRights.BREAK_CYCLES:
            return abort(403, "Access denied")
        try:
            inputs['optional_deps'] = validate_optional_deps(request.form['optional_deps'])
        except ValueError:
            return abort(400, "Bad request")

    if _workflow_dispatch('build.yml', inputs):
        audit_log(g.principal, session['fork'], 'workflow_dispatch', inputs)
    return redirect(url_for('index'))

@app.route("/maint_dispatch", methods=['POST'])
@verify_login_token
def maint_dispatch():
    if app.config['ACL'].check(g.principal, AccessRights.CLEAR_FAILURES) != AccessRights.CLEAR_FAILURES:
        return abort(403, "Access denied")

    inputs = {'context': json.dumps({"principal": str(g.principal)})}
    try:
        if request.form.get('clear_failed_packages'):
            inputs['clear_failed_packages'] = validate_clear_failed_packages(request.form['clear_failed_packages'])

        if request.form.get('clear_failed_build_types'):
            inputs['clear_failed_build_types'] = validate_clear_failed_build_types(request.form['clear_failed_build_types'])
    except ValueError:
        return abort(400, "Bad request")

    if _workflow_dispatch('maint.yml', inputs):
        audit_log(g.principal, session['fork'], 'maint_dispatch', inputs)
    return redirect(url_for('index'))

@app.route("/cancel", methods=['POST'])
@verify_login_token
def cancel():
    if app.config['ACL'].check(g.principal, AccessRights.CANCEL_RUN) != AccessRights.CANCEL_RUN:
        return abort(403, "Access denied")

    repo = _get_autobuild_repo(session['fork'])
    if False:
        if repo.get_workflow_run(request.form['id']).cancel():
            audit_log(g.principal, session['fork'], 'cancel', request.form['id'])
    else:
        # don't need to GET the workflow just to cancel it
        repo._requester.requestJsonAndCheck("POST", f'{repo.url}/actions/runs/{request.form["id"]}/cancel')
        audit_log(g.principal, session['fork'], 'cancel', request.form['id'])
    return redirect(url_for('index'))

@app.route('/login')
def login():
    if g.principal is not None:
        flash("Already logged in!")
        return redirect(url_for('index'))
    else:
        return handle_login()

@app.route('/logout')
def logout():
    if 'user_access_token' in session:
        access_token=decrypt_protected_var(session['user_access_token'])
        requests.delete(f'https://api.github.com/applications/{app.config["GITHUB_CLIENT_ID"]}/token',
                        data=f'{{"access_token":"{access_token}"}}',
                        auth=(app.config["GITHUB_CLIENT_ID"], app.config["GITHUB_CLIENT_SECRET"]))
    clear_login_session()
    return redirect(url_for('index'))

@app.route('/github-callback')
@github_oauth_state_check
def authorized():
    next_url = session.pop('auth_next', None) or url_for('index')

    access_token = oauthapp.get_access_token(request.args['code'], session.get('auth_state'))

    user = Github(access_token.token).get_user()
    principal = Principal(user.type, user.login)
    if principal not in app.config['ACL']:
        flash(f"Sorry, {user.type} {user.login} is not authorized to use this app")
        return redirect(url_for('index'))

    session['user_principal'] = principal
    session['user_access_token'] = encrypt_protected_var(access_token.token)

    return redirect(next_url)

