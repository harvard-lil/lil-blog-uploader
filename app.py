import re
from ast import literal_eval
import boto3
import botocore
import imghdr
import jwt
from os import environ, path
import random
import string
from werkzeug.utils import secure_filename

from flask import Flask, request, redirect, abort, render_template, current_app, g
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms.validators import ValidationError

import error_handling

import logging

app = Flask(__name__)
# Signs the session cookie, which holds only the upload form's CSRF token.
app.config['SECRET_KEY'] = environ.get('FLASK_SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = literal_eval(environ.get('SESSION_COOKIE_SECURE', 'True'))
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['LOG_LEVEL'] = environ.get('LOG_LEVEL', 'WARNING')
# Cloudflare Access: the team domain that signs identity tokens, and the
# audience tag of the Access application in front of this app.
app.config['ACCESS_TEAM_DOMAIN'] = environ.get('ACCESS_TEAM_DOMAIN', 'https://lil.cloudflareaccess.com')
app.config['ACCESS_AUD'] = environ.get('ACCESS_AUD')
# Specific to this proxy
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 ## 16MB
app.config['S3_BUCKET'] = environ.get('S3_BUCKET')

# register error handlers
error_handling.init_app(app)

# PyJWKClient caches Cloudflare's signing keys and refetches when a token
# names a key it has not seen, which is how Access key rotation arrives.
access_keys = jwt.PyJWKClient('{}/cdn-cgi/access/certs'.format(app.config['ACCESS_TEAM_DOMAIN']))


###
### UTILS ###
###

with app.app_context():
    if not app.debug:
        # Flask's default handler already writes to sys.stderr.
        app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))


@app.before_request
def require_access_identity():
    """
    Cloudflare Access admits LIL's Keycloak users and forwards each request
    with a signed identity token. Checking the token here, rather than trusting
    that requests only arrive through Access, keeps the app closed if the Access
    application is ever removed or the app is reached another way.
    """
    if request.endpoint in ('health', 'static'):
        return
    if app.debug and environ.get('DEV_USER_EMAIL'):
        g.user_email = environ['DEV_USER_EMAIL']
        return
    token = request.headers.get('Cf-Access-Jwt-Assertion')
    if not token:
        abort(403)
    try:
        signing_key = access_keys.get_signing_key_from_jwt(token)
        claims = jwt.decode(token, signing_key.key, algorithms=['RS256'],
                            audience=app.config['ACCESS_AUD'],
                            issuer=app.config['ACCESS_TEAM_DOMAIN'])
    except jwt.PyJWKClientConnectionError:
        app.logger.exception("Could not fetch Cloudflare Access signing keys")
        abort(503)
    except jwt.PyJWTError as e:
        app.logger.warning("Rejected Cloudflare Access token: %s", e)
        abort(403)
    if not claims.get('email'):
        abort(403)
    g.user_email = claims['email']


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
        app.logger.info("%s uploaded %s", g.user_email, filename)
        return render_template('success.html', context={'heading': "Your file is up!" ,
                                                        'url': "https://{}.s3.amazonaws.com/{}".format(current_app.config['S3_BUCKET'], filename) })
    return render_template('uploader.html', context={'heading': 'Upload Media', 'limit': current_app.config['MAX_CONTENT_LENGTH']//1024//1024}, form=form)


@app.route('/health')
def health():
    return {"status": "healthy"}, 200


@app.route("/logout")
def logout():
    return redirect('/cdn-cgi/access/logout')
