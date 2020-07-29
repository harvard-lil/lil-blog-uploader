from ast import literal_eval
import boto3
import botocore
from datetime import datetime, timedelta
from functools import wraps
import imghdr
from os import environ, path
import random
import requests
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
REVOKE_TOKEN_URL = 'https://api.github.com/applications/{}/token'.format(app.config['GITHUB_CLIENT_ID'])


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
            return redirect('{}?scope=read:org&client_id={}'.format(AUTHORIZE_URL, app.config['GITHUB_CLIENT_ID']))
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
    'png': 'image/png',
    'gif': 'image/gif'
}

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
    }
}

def get_mime_type(file_name):
    """ Return mime type (for a valid file extension) or None if file extension is unknown. """
    file_extension = file_name.rsplit('.', 1)[-1].lower()
    return file_extension_lookup.get(file_extension)


def filename_already_used(filename):
    """Technique from https://stackoverflow.com/a/33843019"""
    s3 = boto3.resource('s3',
            aws_access_key_id=current_app.config['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=current_app.config['AWS_SECRET_ACCESS_KEY']
    )
    exists = False
    try:
        s3.Object(current_app.config['S3_BUCKET'], filename).load()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            exists = False
        else:
            raise
    else:
        exists = True
    return exists

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
        unique_filename = False
        while not unique_filename:
            if filename_already_used(filename):
                fn, ext = path.splitext(filename)
                filename = '{}-{}{}'.format(fn, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(3)), ext)
                continue
            unique_filename = True
        # Upload to s3
        s3 = boto3.client(
            's3',
            aws_access_key_id=current_app.config['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=current_app.config['AWS_SECRET_ACCESS_KEY'],
        )
        s3.upload_fileobj(f.stream, 'lil-blog-media', filename, ExtraArgs={'ContentType': get_mime_type(filename)})
        return render_template('success.html', context={'heading': "Your file is up!" ,
                                                        'url': "https://{}.s3.amazonaws.com/{}".format(current_app.config['S3_BUCKET'], filename) })
    return render_template('uploader.html', context={'heading': 'Upload Media', 'limit': current_app.config['MAX_CONTENT_LENGTH']//1024//1024}, form=form)


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

    if scope == 'read:org':
        app.logger.debug("Requesting User Organization Info")
        r = requests.get(ORGS_URL, headers={'accept': 'application/json',
                                            'authorization': 'token {}'.format(access_token)})

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
                if next and is_safe_url(next):
                    return redirect(next)
                return redirect(url_for('landing'))
            else:
                app.logger.warning("Log in attempt from Github user who is not a member of LIL.")
                abort(401)
        else:
            app.logger.error("Failed request for user orgs. Gitub says {}".format(data['message']))
            abort(500)
    else:
        app.logger.warning("Insufficient scope authorized in Github; verify API hasn't changed.")
        abort(401)
