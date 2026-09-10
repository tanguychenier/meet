"""Application hashing and migration of existing credentials."""

import hashlib
from unittest import mock

from django.contrib.auth.hashers import check_password, identify_hasher, make_password
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils.crypto import get_random_string

import pytest
from rest_framework.test import APIClient

from core import hashers
from core.factories import ApplicationFactory, UserFactory
from core.models import Application

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("secret", ["short", "a" * 128, b"byte-secret"])
def test_application_hash(secret):
    """Application hashes verify correctly but are not accepted for user passwords."""
    encoded = hashers.hash_client_secret(secret)
    raw = secret.encode() if isinstance(secret, str) else secret
    assert encoded == f"sha256${hashlib.sha256(raw).hexdigest()}"
    assert hashers.verify_client_secret(secret, encoded)
    assert not hashers.verify_client_secret("wrong", encoded)
    assert not hashers.verify_client_secret(None, encoded)
    assert not hashers.verify_client_secret(secret, "sha256$invalid")
    assert not check_password(secret, encoded)
    with pytest.raises(ValueError):
        identify_hasher(encoded)
    assert not make_password(raw.decode()).startswith("sha256$")


@pytest.mark.parametrize("algorithm", ["pbkdf2_sha256", "md5"])
def test_token_migrates_legacy_secret_once(algorithm):
    """The same client secret works before and after migration, with no later writes."""
    secret = get_random_string(128)
    user = UserFactory()
    legacy = make_password(secret, hasher=algorithm)
    app = ApplicationFactory(client_secret=legacy)
    app.refresh_from_db()

    assert app.client_secret == legacy
    payload = {
        "client_id": app.client_id,
        "client_secret": secret,
        "grant_type": "client_credentials",
        "scope": user.email,
    }
    client = APIClient()
    response = client.post(
        "/external-api/v1.0/application/token/", payload, format="json"
    )
    assert response.status_code == 200
    app.refresh_from_db()
    migrated = app.client_secret
    assert migrated == hashers.hash_client_secret(secret)
    with CaptureQueriesContext(connection) as queries:
        response = client.post(
            "/external-api/v1.0/application/token/", payload, format="json"
        )
    assert response.status_code == 200
    assert not any(q["sql"].lstrip().startswith("UPDATE") for q in queries)
    app.refresh_from_db()
    assert app.client_secret == migrated


def test_wrong_secret_does_not_migrate():
    """Failed authentication leaves a production PBKDF2 hash untouched."""
    user = UserFactory()
    legacy = make_password(get_random_string(128), hasher="pbkdf2_sha256")
    app = ApplicationFactory(client_secret=legacy)
    response = APIClient().post(
        "/external-api/v1.0/application/token/",
        {
            "client_id": app.client_id,
            "client_secret": "wrong",
            "grant_type": "client_credentials",
            "scope": user.email,
        },
        format="json",
    )
    assert response.status_code == 401
    app.refresh_from_db()
    assert app.client_secret == legacy


def test_migration_preserves_concurrent_rotation():
    """Migration must not restore a secret rotated after verification."""
    secret = get_random_string(128)
    app = ApplicationFactory(
        client_secret=make_password(secret, hasher="pbkdf2_sha256")
    )
    replacement = hashers.hash_client_secret(get_random_string(128))

    def verify_then_rotate(raw, encoded):
        verified = check_password(raw, encoded)
        Application.objects.filter(pk=app.pk).update(client_secret=replacement)
        return verified

    with mock.patch.object(hashers, "check_password", side_effect=verify_then_rotate):
        assert app.check_client_secret(secret) is False

    app.refresh_from_db()
    assert app.client_secret == replacement


def test_migration_preserves_concurrent_migration():
    """Authentication succeeds when another request migrates the same secret."""
    secret = get_random_string(128)
    app = ApplicationFactory(
        client_secret=make_password(secret, hasher="pbkdf2_sha256")
    )
    migrated = hashers.hash_client_secret(secret)

    def verify_then_migrate(raw, encoded):
        verified = check_password(raw, encoded)
        Application.objects.filter(pk=app.pk).update(client_secret=migrated)
        return verified

    with mock.patch.object(hashers, "check_password", side_effect=verify_then_migrate):
        assert app.check_client_secret(secret) is True

    app.refresh_from_db()
    assert app.client_secret == migrated


def test_migration_preserves_concurrent_deletion():
    """Authentication fails when the application is deleted after verification."""
    secret = get_random_string(128)
    app = ApplicationFactory(
        client_secret=make_password(secret, hasher="pbkdf2_sha256")
    )

    def verify_then_delete(raw, encoded):
        verified = check_password(raw, encoded)
        Application.objects.filter(pk=app.pk).delete()
        return verified

    with mock.patch.object(hashers, "check_password", side_effect=verify_then_delete):
        assert app.check_client_secret(secret) is False

    assert not Application.objects.filter(pk=app.pk).exists()
