from os import environ
from ast import literal_eval
import requests
from functools import wraps
from urlparse import urlparse, urljoin
from datetime import datetime, timedelta

from flask import Flask, request, redirect, session, abort, url_for, render_template
import error_handling
from proxy import proxy_request

import logging

app = Flask(__name__)
app.config['GITHUB_CLIENT_ID'] = environ.get('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = environ.get('GITHUB_CLIENT_SECRET')
app.config['GITHUB_ORG_NAME'] = environ.get('GITHUB_ORG_NAME')
app.config['SECRET_KEY'] = environ.get('FLASK_SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = literal_eval(environ.get('SESSION_COOKIE_SECURE', 'True'))
app.config['LOGIN_EXPIRY_MINUTES'] = environ.get('LOGIN_EXPIRY', 30)
app.config['LOG_LEVEL'] = environ.get('LOG_LEVEL', 'WARNING')
# Specific to this proxy
app.config['MAX_CONTENT_LENGTH'] = environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024) ## 16MB
app.config['S3_BUCKET'] = environ.get('S3_BUCKET')
app.config['AWS_ACCESS_KEY_ID'] = environ.get('AWS_ACCESS_KEY_ID')
app.config['AWS_SECRET_ACCESS_KEY'] = environ.get('AWS_SECRET_ACCESS_KEY')

# register error handlers
error_handling.init_app(app)

AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'
ORGS_URL = 'https://api.github.com/user/orgs'
REVOKE_TOKEN_URL = 'https://api.github.com/applications/{}/tokens/'.format(app.config['GITHUB_CLIENT_ID'])


###
### UTILS ###
###

@app.before_first_request
def setup_logging():
    if not app.debug:
        # In production mode, add log handler to sys.stderr.
        app.logger.addHandler(logging.StreamHandler())
        app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))

def login_required(func):
    @wraps(func)
    def handle_login(*args, **kwargs):
        logged_in = session.get('logged_in')
        valid_until = session.get('valid_until')
        if valid_until:
            valid = datetime.strptime(valid_until, '%Y-%m-%d %H:%M:%S') > datetime.utcnow()
        else:
            valid = False
        if logged_in and logged_in == "yes" and valid:
            app.logger.debug("User session valid")
            return func(*args, **kwargs)
        else:
            app.logger.debug("Redirecting to GitHub")
            session['next'] = request.url
            return redirect('{}?scope=user&client_id={}'.format(AUTHORIZE_URL, app.config['GITHUB_CLIENT_ID']))
    return handle_login

def is_safe_url(target):
    '''
        Ensure a url is safe to redirect to, from WTForms
        http://flask.pocoo.org/snippets/63/from WTForms
    '''
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

###
### ROUTES
###

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>')
@login_required
def catch_all(path):
    '''
        All requests are caught by this route, unless explicitly caught by
        other more specific patterns.
        http://flask.pocoo.org/docs/0.12/design/#the-routing-system
    '''
    def fallback():
        return render_template('generic.html', context={'heading': "lil blog media uploader",
                                                        'message': "a static site helper"})

    try:
        proxied_response = proxy_request(request, path)
        if proxied_response:
            return proxied_response
        else:
            app.logger.warning("No response returned by proxied endpoint.")
            return fallback()
    except NameError:
        app.logger.warning("No proxy function available.")
        return fallback()


@app.route('/login')
def login():
    return render_template('login.html', context={'heading': 'Log In', 'client_id': app.config['GITHUB_CLIENT_ID']})

@app.route("/logout")
def logout():
    session.clear()
    return render_template('generic.html', context={'heading': "Logged Out",
                                                    'message': "You have successfully been logged out."})

@app.route('/auth/github/callback')
def authorized():
    app.logger.debug("Requesting Access Token")
    r = requests.post(ACCESS_TOKEN_URL, headers={'accept': 'application/json'},
                                        data={'client_id': app.config['GITHUB_CLIENT_ID'],
                                              'client_secret': app.config['GITHUB_CLIENT_SECRET'],
                                              'code': request.args.get('code')})
    data = r.json()
    if r.status_code == 200:
        access_token = data.get('access_token')
        scope = data.get('scope')
        app.logger.debug("Received Access Token")
    else:
        app.logger.error("Failed request for access token. Gitub says {}".format(data['message']))
        abort(500)

    if scope == 'user':
        app.logger.debug("Requesting User Organization Info")
        r = requests.get(ORGS_URL, headers={'accept': 'application/json',
                                            'authorization': 'token {}'.format(access_token)})

        app.logger.debug("Revoking Github Access Token")
        d = requests.delete(REVOKE_TOKEN_URL + access_token, auth=(app.config['GITHUB_CLIENT_ID'], app.config['GITHUB_CLIENT_SECRET']))
        app.logger.debug("(Request returned {})".format(d.status_code))

        data = r.json()
        if r.status_code == 200:
            if data and any(org['login'] == app.config['GITHUB_ORG_NAME'] for org in data):
                next = session.get('next')
                session.clear()
                valid_until = (datetime.utcnow() + timedelta(seconds=60*30)).strftime('%Y-%m-%d %H:%M:%S')
                session['valid_until'] = valid_until
                session['logged_in'] = "yes"
                if next and is_safe_url(next):
                    return redirect(next)
                return redirect(url_for('catch_all'))
            else:
                app.logger.warning("Log in attempt from Github user who is not a member of LIL.")
                abort(401)
        else:
            app.logger.error("Failed request for user orgs. Gitub says {}".format(data['message']))
            abort(500)
    else:
        app.logger.warning("Insufficient scope authorized in Github; verify API hasn't changed.")
        abort(401)
