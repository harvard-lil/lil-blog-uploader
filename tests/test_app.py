import io
import logging
import re
import time
from unittest import mock

import boto3
import pytest
from botocore.stub import ANY, Stubber
from cryptography.hazmat.primitives.asymmetric import rsa

PNG = b'\x89PNG\r\n\x1a\n' + b'\0' * 32
JPEG_ICC = b'\xff\xd8\xff\xe2' + b'\0' * 32  # a JPEG that opens with an ICC profile segment
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"></svg>'


def headers(token):
    return {'Cf-Access-Jwt-Assertion': token}


def csrf_token(client, token):
    page = client.get('/', headers=headers(token)).get_data(as_text=True)
    return re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', page).group(1)


@pytest.fixture
def s3():
    """A stubbed S3 client, handed to the app in place of a real one."""
    s3 = boto3.client('s3', region_name='us-east-1')
    stubber = Stubber(s3)
    with mock.patch('boto3.client', lambda *args, **kwargs: s3), stubber:
        yield stubber
        stubber.assert_no_pending_responses()


def expected_put(key=ANY, content_type=ANY, **extra):
    return {'Bucket': 'lil-blog-media', 'Key': key, 'Body': ANY, 'ContentType': content_type,
            'IfNoneMatch': '*', **extra}


def upload(client, token, content, filename, with_csrf=True):
    data = {'file': (io.BytesIO(content), filename)}
    if with_csrf:
        data['csrf_token'] = csrf_token(client, token)
    return client.post('/', headers=headers(token), data=data, content_type='multipart/form-data')


def test_health_needs_no_token(client):
    assert client.get('/health').status_code == 200


def test_missing_token_is_forbidden(client):
    assert client.get('/').status_code == 403


@pytest.mark.parametrize('claims', [
    {'aud': ['another-application']},
    {'iss': 'https://elsewhere.cloudflareaccess.com'},
    {'exp': int(time.time()) - 10},
    {'email': None},
])
def test_invalid_tokens_are_forbidden(client, make_token, claims):
    assert client.get('/', headers=headers(make_token(**claims))).status_code == 403


def test_token_from_another_key_is_forbidden(client, make_token):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert client.get('/', headers=headers(make_token(key=other_key))).status_code == 403


def test_upload_page(client, make_token):
    response = client.get('/', headers=headers(make_token()))
    assert response.status_code == 200
    assert 'Upload Media' in response.get_data(as_text=True)


def test_upload(client, make_token, s3, caplog):
    caplog.set_level(logging.INFO, logger='app')
    s3.add_response('put_object', {}, expected_put('photo.png', 'image/png'))
    response = upload(client, make_token(), PNG, 'photo.png')
    assert 'https://lil-blog-media.s3.amazonaws.com/photo.png' in response.get_data(as_text=True)
    assert 'someone@law.harvard.edu uploaded photo.png' in caplog.text


def test_upload_under_taken_name_gets_suffix(client, make_token, s3):
    s3.add_client_error('put_object', service_error_code='PreconditionFailed', http_status_code=412,
                        expected_params=expected_put('photo.png'))
    s3.add_response('put_object', {}, expected_put())
    response = upload(client, make_token(), PNG, 'photo.png')
    assert re.search(r'/photo-[A-Z0-9]{3}\.png', response.get_data(as_text=True))


def test_svg_is_served_as_attachment(client, make_token, s3):
    s3.add_response('put_object', {}, expected_put('logo.svg', 'image/svg+xml', ContentDisposition='attachment'))
    upload(client, make_token(), SVG, 'logo.svg')


def test_jpeg_with_icc_profile_is_accepted(client, make_token, s3):
    s3.add_response('put_object', {}, expected_put('photo.jpg', 'image/jpeg'))
    upload(client, make_token(), JPEG_ICC, 'photo.jpg')


def test_name_without_ascii_characters_gets_a_generated_one(client, make_token, s3):
    s3.add_response('put_object', {}, expected_put())
    response = upload(client, make_token(), PNG, '图片.png')
    assert re.search(r'/upload-[A-Z0-9]{3}\.png', response.get_data(as_text=True))


@pytest.mark.parametrize('content, filename', [
    (b'not really an image', 'photo.png'),
    (PNG, 'photo.exe'),
    (b'\xff\xfe not utf-8', 'logo.svg'),
])
def test_invalid_files_are_rejected(client, make_token, content, filename):
    response = upload(client, make_token(), content, filename)
    assert response.status_code == 200
    assert 'Invalid file format' in response.get_data(as_text=True)


def test_upload_without_csrf_token_is_rejected(client, make_token):
    response = upload(client, make_token(), PNG, 'photo.png', with_csrf=False)
    assert 'CSRF' in response.get_data(as_text=True)


def test_logout_goes_to_access(client, make_token):
    response = client.get('/logout', headers=headers(make_token()))
    assert response.headers['Location'] == '/cdn-cgi/access/logout'
