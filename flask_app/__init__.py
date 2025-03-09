
# A very simple Flask Hello World app for you to get started with...

import functools
import hmac
import json
import requests
import secrets
import sys
import logging
import urllib.parse

from cryptography.fernet import Fernet
from flask import Flask, request, abort, session, g, url_for, redirect, flash, render_template
from github.Repository import Repository
from github import Github, GithubIntegration
from github.Auth import AppAuth, AppInstallationAuth
from github.Workflow import Workflow

from .validate_autobuild_inputs import validate_optional_deps, validate_clear_failed_build_types, validate_clear_failed_packages
from .permissions import Principal, AccessRights, AccessControlList


app = Flask(__name__, instance_relative_config=True)
# XXX do I care about default settings?
app.config.from_pyfile('application.cfg', silent=True)

with app.open_instance_resource(app.config['GITHUB_APP_KEY_FILE']) as keyfile:
    data = keyfile.read()
    assert isinstance(data, bytes)
    app.config['GITHUB_APP_KEY'] = data.decode()

GH_DEFAULTS = {
    "seconds_between_requests": 0,
    "lazy": True
}

ACL: AccessControlList = app.config['ACL']

appauth = AppAuth(app.config['GITHUB_APP_ID'], app.config['GITHUB_APP_KEY'])
githubintegration = GithubIntegration(auth=appauth, **GH_DEFAULTS)
oauthapp = Github(**GH_DEFAULTS).get_oauth_application(app.config["GITHUB_CLIENT_ID"], app.config["GITHUB_CLIENT_SECRET"])

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)

logger = logging.getLogger(app.name)


def audit_log(principal: Principal, fork: str, action: str, params: dict[str, str]):
    logger.info(f"AUDIT LOG: {principal} {fork} {action} {params!r}")


def encrypt_protected_var(cleartext: str) -> str:
    return Fernet(app.config['FERNET_SECRET_KEY'].encode('utf-8')).encrypt(cleartext.encode('utf-8')).decode('utf-8')


def decrypt_protected_var(ciphertext: str) -> str:
    return Fernet(app.config['FERNET_SECRET_KEY'].encode('utf-8')).decrypt(ciphertext.encode('utf-8')).decode('utf-8')


def _get_autobuild_repo(fork: str, *, _gh_cache: dict[int, Github] = {}) -> Repository:
    if fork not in _gh_cache:
        installation = githubintegration.get_repo_installation(fork, 'msys2-autobuild')
        auth = AppInstallationAuth(
            appauth, installation.id, {"actions": "write", "metadata": "read"})
        _gh_cache[fork] = Github(auth=auth, **GH_DEFAULTS)
    gh = _gh_cache[fork]
    return gh.get_repo(fork + '/msys2-autobuild', lazy=True)


def clear_login_session():
    [session.pop(key) for key in list(session.keys()) if key.startswith('user_')]


def handle_login(next=None):
    session['auth_state'] = secrets.token_urlsafe()
    if next:
        session['auth_next'] = next
    redirect_uri = url_for('authorized', _external=True)
    return redirect(oauthapp.get_login_url(state=session['auth_state'], redirect_uri=redirect_uri))


def verify_github_webhook_signature(func):
    @functools.wraps(func)
    def wrapper_github_webhook_signature_verification(*args, **kwargs):
        signature = "sha256=" + hmac.digest(
            app.config['GITHUB_WEBHOOK_SECRET'].encode('utf-8'),
            request.data,
            'SHA256'
        ).hex().lower()
        if not hmac.compare_digest(signature, request.headers['X-Hub-Signature-256']):
            return abort(401, 'Bad digest')
        return func(*args, **kwargs)
    return wrapper_github_webhook_signature_verification


def check_app_token(access_token: str) -> bool:
    # https://docs.github.com/en/rest/apps/oauth-applications#check-a-token
    client_id = urllib.parse.quote(app.config["GITHUB_CLIENT_ID"])
    resp = requests.post(f'https://api.github.com/applications/{client_id}/token',
                         data=f'{{"access_token":"{access_token}"}}',
                         auth=(app.config["GITHUB_CLIENT_ID"], app.config["GITHUB_CLIENT_SECRET"]))
    return resp.ok


def verify_login_token(func):
    @functools.wraps(func)
    def wrapper_verify_login_token(*args, **kwargs):
        is_valid = False
        if 'user_access_token' in session:
            access_token = decrypt_protected_var(session['user_access_token'])
            is_valid = check_app_token(access_token)
        if not is_valid:
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


def get_lazy_repo_workflow(repo: Repository, id_or_file_name: str | int) -> Workflow:
    # XXX: We only need the Workflow to get to the runs, so make it lazy
    id_or_file_name = urllib.parse.quote(str(id_or_file_name))
    return Workflow(repo._requester, {}, {
        'name': str(id_or_file_name),
        'url': f'{repo.url}/actions/workflows/{id_or_file_name}'}, completed=False)


@verify_login_token
def authenticated_index():
    if 'fork' in request.values and request.values['fork'] in app.config['AUTOBUILD_FORKS']:
        session['fork'] = request.values['fork']
    elif 'fork' not in session:
        session['fork'] = sorted(app.config['AUTOBUILD_FORKS'])[0]

    if request.method == 'POST':
        return redirect(url_for(request.endpoint, **request.view_args))

    repo = _get_autobuild_repo(session['fork'])
    workflow = get_lazy_repo_workflow(repo, 'build.yml')
    runs = workflow.get_runs().get_page(0)
    return render_template('index.html', runs=runs, ACL=ACL, AccessRights=AccessRights)


@app.route('/trigger')
def trigger():
    if not g.principal:
        return handle_login(url_for(request.endpoint, **request.view_args))
    if not ACL.is_granted(g.principal, AccessRights.TRIGGER_RUN):
        return abort(403, "Access denied")
    return render_template('trigger.html', ACL=ACL, AccessRights=AccessRights)


@app.route('/maint')
def maint():
    if not g.principal:
        return handle_login(url_for(request.endpoint, **request.view_args))
    if not ACL.is_granted(g.principal, AccessRights.CLEAR_FAILURES):
        return abort(403, "Access denied")
    return render_template('maint.html', ACL=ACL, AccessRights=AccessRights)


@app.route("/github-webhook", methods=['POST'])
@verify_github_webhook_signature
def github_webhook():
    return "Got it"


def _workflow_dispatch(workflow_yml: str, inputs) -> bool:
    repo = _get_autobuild_repo(session['fork'])
    workflow = get_lazy_repo_workflow(repo, workflow_yml)
    return workflow.create_dispatch(repo.default_branch, inputs=inputs)


@app.route("/workflow_dispatch", methods=['POST'])
@verify_login_token
def workflow_dispatch():
    if not ACL.is_granted(g.principal, AccessRights.TRIGGER_RUN):
        return abort(403, "Access denied")

    inputs = {'context': json.dumps({"principal": str(g.principal)})}
    if request.form.get('optional_deps'):
        if not ACL.is_granted(g.principal, AccessRights.BREAK_CYCLES):
            return abort(403, "Access denied")
        try:
            inputs['optional_deps'] = validate_optional_deps(request.form['optional_deps'])
        except ValueError:
            return abort(400, "Bad request")

    if _workflow_dispatch('build.yml', inputs):
        audit_log(g.principal, session['fork'], 'workflow_dispatch', inputs)
        flash("Workflow run was successfully requested")
    return redirect(url_for('index'))


@app.route("/maint_dispatch", methods=['POST'])
@verify_login_token
def maint_dispatch():
    if not ACL.is_granted(g.principal, AccessRights.CLEAR_FAILURES):
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
        flash("Maintenance workflow run was successfully requested")
    return redirect(url_for('index'))


@app.route("/cancel", methods=['POST'])
@verify_login_token
def cancel():
    if not ACL.is_granted(g.principal, AccessRights.CANCEL_RUN):
        return abort(403, "Access denied")

    repo = _get_autobuild_repo(session['fork'])
    if repo.get_workflow_run(int(request.form['id'])).cancel():
        audit_log(g.principal, session['fork'], 'cancel', request.form['id'])
        flash("Workflow run was successfully cancelled")
    return redirect(url_for('index'))


@app.route('/login')
def login():
    if g.principal is not None:
        flash("Already logged in!")
        return redirect(url_for('index'))
    else:
        return handle_login()


def revoke_app_token(access_token: str) -> bool:
    # https://docs.github.com/en/rest/apps/oauth-applications#delete-an-app-token
    client_id = urllib.parse.quote(app.config["GITHUB_CLIENT_ID"])
    resp = requests.delete(
        f'https://api.github.com/applications/{client_id}/token',
        data=f'{{"access_token":"{access_token}"}}',
        auth=(app.config["GITHUB_CLIENT_ID"], app.config["GITHUB_CLIENT_SECRET"]))
    return resp.status_code == 204


@app.route('/logout')
def logout():
    if 'user_access_token' in session:
        access_token = decrypt_protected_var(session['user_access_token'])
        revoke_app_token(access_token)
    clear_login_session()
    return redirect(url_for('index'))


@app.route('/github-callback')
def authorized():
    if 'auth_state' in session and 'state' in request.args:
        if not secrets.compare_digest(session['auth_state'], request.args['state']):
            return abort(401, 'Bad CSRF token')
    else:
        return abort(401, 'Missing CSRF token')

    next_url = session.pop('auth_next', None) or url_for('index')

    access_token = oauthapp.get_access_token(request.args['code'], session.get('auth_state'))

    auth = oauthapp.get_app_user_auth(access_token)
    user = Github(auth=auth, **GH_DEFAULTS).get_user()
    principal = Principal(user.type, user.login)
    if principal not in ACL:
        flash(f"Sorry, {user.type} {user.login} is not authorized to use this app")
        return redirect(url_for('index'))

    session['user_principal'] = principal
    session['user_access_token'] = encrypt_protected_var(access_token.token)

    return redirect(next_url)
