"""Application secrets only: keep fast hashing out of PASSWORD_HASHERS.

Secrets must be securely randomly generated, not human-chosen.
"""

import hashlib

from django.contrib.auth.hashers import check_password
from django.utils.crypto import constant_time_compare
from django.utils.encoding import force_bytes


def hash_client_secret(raw_secret):
    """Hash a machine-generated application secret without key stretching."""
    return f"sha256${hashlib.sha256(force_bytes(raw_secret)).hexdigest()}"


def verify_client_secret(raw_secret, encoded):
    """Verify the application format or a legacy Django password hash."""
    if raw_secret is None:
        return False
    if encoded.startswith("sha256$"):
        return constant_time_compare(encoded, hash_client_secret(raw_secret))
    return check_password(raw_secret, encoded)
