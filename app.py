import re
from ast import literal_eval
import boto3
import botocore
from datetime import datetime, timedelta
from functools import wraps
import imghdr
from os import environ, path
import random
import requests
import secrets
import string
from urllib.parse import urlparse, urljoin
from werkzeug.utils import secure_filename

from flask import Flask, request, redirect, session, abort, url_for, render_template, current_app
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms.validators import ValidationError

import error_handling

import logging

app = Flask(__name__)
app.config['GITHUB_CLIENT_ID'] = environ.get('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = environ.get('GITHUB_CLIENT_SECRET')
app.config['GITHUB_ORG_NAME'] = environ.get('GITHUB_ORG_NAME')
app.config['SECRET_KEY'] = environ.get('FLASK_SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = literal_eval(environ.get('SESSION_COOKIE_SECURE', 'True'))
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['LOGIN_EXPIRY_MINUTES'] = environ.get('LOGIN_EXPIRY', 30)
app.config['LOG_LEVEL'] = environ.get('LOG_LEVEL', 'WARNING')
# Specific to this proxy
app.config['MAX_CONTENT_LENGTH'] = environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024) ## 16MB
app.config['S3_BUCKET'] = environ.get('S3_BUCKET')

# register error handlers
error_handling.init_app(app)

AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'
USER_URL = 'https://api.github.com/user'
ORGS_URL = 'https://api.github.com/user/orgs'
REVOKE_TOKEN_URL = 'https://api.github.com/applications/{}/token'.format(app.config['GITHUB_CLIENT_ID'])


###
### UTILS ###
###

with app.app_context():
    if not app.debug:
        # Flask's default handler already writes to sys.stderr.
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
            # Ties the callback to this browser's login attempt.
            session['oauth_state'] = secrets.token_urlsafe(32)
            return redirect('{}?scope=read:org&client_id={}&state={}'.format(
                AUTHORIZE_URL, app.config['GITHUB_CLIENT_ID'], session['oauth_state']))
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


#
# Mime typing checking, taken straight from Perma (more rigorous than WTForms)
#

# Map allowed file extensions to mime types.
# WARNING: If you change this, also change `accept=""` and the label in
# uploader.html
file_extension_lookup = {
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'pdf': 'application/pdf',
    'png': 'image/png',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'svg': 'image/svg+xml'
}

def validate_pdf(file):
    valid = b'%PDF-' in file.read(10)
    file.seek(0)
    return valid

# Source: https://stackoverflow.com/a/63419911
def validate_svg(file):
    regex = re.compile(
        r'(?:<\?xml\b[^>]*>[^<]*)?(?:<!--.*?-->[^<]*)*(?:<svg|<!DOCTYPE svg)\b',
        re.DOTALL
    )

    contents = file.read().decode('utf-8')

    file.seek(0)

    return regex.match(contents) is not None

# Map allowed mime types to new file extensions and validation functions.
# We manually pick the new extension instead of using MimeTypes().guess_extension,
# because that varies between systems.
mime_type_lookup = {
    'image/jpeg': {
        'new_extension': 'jpg',
        'valid_file': lambda f: imghdr.what(f) == 'jpeg',
    },
    'image/png': {
        'new_extension': 'png',
        'valid_file': lambda f: imghdr.what(f) == 'png',
    },
    'image/gif': {
        'new_extension': 'gif',
        'valid_file': lambda f: imghdr.what(f) == 'gif',
    },
    'image/webp': {
        'new_extension': 'webp',
        'valid_file': lambda f: imghdr.what(f) == 'webp',
    },
    'image/svg+xml': {
        'new_extension': 'svg',
        'valid_file': validate_svg
    },
    'application/pdf': {
        'new_extension': 'pdf',
        'valid_file': validate_pdf,
    }
}

def get_mime_type(file_name):
    """ Return mime type (for a valid file extension) or None if file extension is unknown. """
    file_extension = file_name.rsplit('.', 1)[-1].lower()
    return file_extension_lookup.get(file_extension)


def random_suffix():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(3))


def upload_new_object(f, filename):
    """
    Upload f under filename, or under filename with a random suffix if that
    key is taken. Returns the key used. If-None-Match makes S3 refuse to
    replace an existing object, so an upload never overwrites published media;
    the task role's policy requires the header.
    """
    s3 = boto3.client('s3')
    mime_type = get_mime_type(filename)
    extra_args = {}
    if mime_type == 'image/svg+xml':
        # <img> tags ignore Content-Disposition, so the blog can still embed
        # the file; opening its URL directly downloads it rather than running
        # any script it contains.
        extra_args['ContentDisposition'] = 'attachment'
    key = filename
    while True:
        f.stream.seek(0)
        try:
            s3.put_object(Bucket=current_app.config['S3_BUCKET'], Key=key, Body=f.stream,
                          ContentType=mime_type, IfNoneMatch='*', **extra_args)
            return key
        except botocore.exceptions.ClientError as e:
            # PreconditionFailed: the key exists. ConditionalRequestConflict:
            # another upload to the same key is in flight.
            if e.response['Error']['Code'] not in ('PreconditionFailed', 'ConditionalRequestConflict'):
                raise
        fn, ext = path.splitext(filename)
        key = '{}-{}{}'.format(fn, random_suffix(), ext)

#
# WTForms custom validators
#

def valid_mimetype(form, field):
    mime_type = get_mime_type(field.data.filename)
    if not mime_type or not mime_type_lookup[mime_type]['valid_file'](field.data):
        raise ValidationError("Invalid file format")

class UploadForm(FlaskForm):
    file = FileField(validators=[FileRequired(), valid_mimetype],
                     label="valid formats: {}".format(", ".join(file_extension_lookup.keys())))


###
### ROUTES
###

@app.route('/', methods=['GET', 'POST'])
@login_required
def landing():
    form = UploadForm()
    if form.validate_on_submit():
        # Get a safe filename
        f = form.file.data
        filename = secure_filename(f.filename)
        # secure_filename drops non-ASCII characters, which can leave only the
        # extension (or nothing) behind.
        fn, ext = path.splitext(filename)
        if not fn or not ext:
            filename = 'upload-{}.{}'.format(random_suffix(), f.filename.rsplit('.', 1)[-1].lower())
        filename = upload_new_object(f, filename)
        app.logger.info("%s uploaded %s", session.get('github_login'), filename)
        return render_template('success.html', context={'heading': "Your file is up!" ,
                                                        'url': "https://{}.s3.amazonaws.com/{}".format(current_app.config['S3_BUCKET'], filename) })
    return render_template('uploader.html', context={'heading': 'Upload Media', 'limit': current_app.config['MAX_CONTENT_LENGTH']//1024//1024}, form=form)


@app.route('/health')
def health():
    return {"status": "healthy"}, 200


@app.route("/logout")
def logout():
    session.clear()
    return render_template('generic.html', context={'heading': "Logged Out",
                                                    'message': "You have successfully been logged out."})

@app.route('/auth/github/callback')
def authorized():
    expected_state = session.pop('oauth_state', None)
    if not expected_state or not secrets.compare_digest(expected_state, request.args.get('state', '')):
        app.logger.warning("GitHub callback without a matching login attempt.")
        abort(400)

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

    if scope == 'read:org':
        app.logger.debug("Requesting User Organization Info")
        auth_headers = {'accept': 'application/json',
                        'authorization': 'token {}'.format(access_token)}
        r = requests.get(ORGS_URL, headers=auth_headers)
        u = requests.get(USER_URL, headers=auth_headers)
        github_login = u.json().get('login') if u.status_code == 200 else None

        app.logger.debug("Revoking Github Access Token")
        d = requests.delete(REVOKE_TOKEN_URL,
                            auth=(app.config['GITHUB_CLIENT_ID'], app.config['GITHUB_CLIENT_SECRET']),
                            json={'access_token': access_token})
        app.logger.debug("(Request returned {})".format(d.status_code))

        data = r.json()
        if r.status_code == 200:
            if data and any(org['login'] == app.config['GITHUB_ORG_NAME'] for org in data):
                next = session.get('next')
                session.clear()
                valid_until = (datetime.utcnow() + timedelta(seconds=60*30)).strftime('%Y-%m-%d %H:%M:%S')
                session['valid_until'] = valid_until
                session['logged_in'] = "yes"
                session['github_login'] = github_login
                app.logger.info("%s logged in", github_login)
                if next and is_safe_url(next):
                    return redirect(next)
                return redirect(url_for('landing'))
            else:
                app.logger.warning("Log in attempt from Github user %s, who is not a member of LIL.", github_login)
                abort(401)
        else:
            app.logger.error("Failed request for user orgs. Gitub says {}".format(data['message']))
            abort(500)
    else:
        app.logger.warning("Insufficient scope authorized in Github; verify API hasn't changed.")
        abort(401)
