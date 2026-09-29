import os
import time
from unittest import mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

# app.py reads its settings at import time.
os.environ.update(
    FLASK_SECRET_KEY='test-secret-key',
    S3_BUCKET='lil-blog-media',
    ACCESS_AUD='test-audience',
    AWS_ACCESS_KEY_ID='testing',
    AWS_SECRET_ACCESS_KEY='testing',
    AWS_DEFAULT_REGION='us-east-1',
)

import app as uploader  # noqa: E402 -- after the environment above

ISSUER = 'https://lil.cloudflareaccess.com'


@pytest.fixture(scope='session')
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def access_keys(signing_key, monkeypatch):
    """Serve the test key in place of Cloudflare's published signing keys."""
    monkeypatch.setattr(uploader.access_keys, 'get_signing_key_from_jwt',
                        lambda token: mock.Mock(key=signing_key.public_key()))


@pytest.fixture
def make_token(signing_key):
    def make(key=None, **claims):
        now = int(time.time())
        payload = {'aud': ['test-audience'], 'iss': ISSUER, 'email': 'someone@law.harvard.edu',
                   'iat': now, 'exp': now + 300}
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not None}
        return jwt.encode(payload, key or signing_key, algorithm='RS256')
    return make


@pytest.fixture
def client():
    return uploader.app.test_client()
