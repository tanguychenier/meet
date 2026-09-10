"""
Core application fields
"""

from logging import getLogger

from django.contrib.auth.hashers import identify_hasher
from django.db import models

from .hashers import hash_client_secret

logger = getLogger(__name__)


class SecretField(models.CharField):
    """CharField that automatically hashes secrets before saving.

    Use for API keys, client secrets, or tokens that should never be stored
    in plain text. Already-hashed values are preserved to prevent double-hashing.

    Inspired by: https://github.com/django-oauth-toolkit/django-oauth-toolkit
    """

    def pre_save(self, model_instance, add):
        """Hash the secret if not already hashed, otherwise preserve it."""

        secret = getattr(model_instance, self.attname)

        if secret.startswith("sha256$"):
            logger.debug(
                "%s: %s is already hashed with sha256.",
                model_instance,
                self.attname,
            )
            return secret

        try:
            hasher = identify_hasher(secret)
            logger.debug(
                "%s: %s is already hashed with %s.",
                model_instance,
                self.attname,
                hasher,
            )
        except ValueError:
            logger.debug(
                "%s: %s is not hashed; hashing it now.", model_instance, self.attname
            )
            hashed_secret = hash_client_secret(secret)
            setattr(model_instance, self.attname, hashed_secret)
            return hashed_secret

        return super().pre_save(model_instance, add)
