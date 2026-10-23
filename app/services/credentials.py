"""Credentials at rest: the SIEM, connector, GitLab and Keycloak secrets TIDE stores.

They are encrypted with a key kept in ``data/credentials.key``, which TIDE creates on first start.
A stored value reads ``enc:v1:<token>``; anything without that prefix is a value from before
encryption, which reveal() returns unchanged and TIDE encrypts at its next start.

Keep the key with the databases: copying data/ to new hardware carries it. Without it the stored
credentials can't be read, and each must be entered again.
"""
import logging
import os
import threading
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

PREFIX = "enc:v1:"
KEY_FILE = "credentials.key"
_lock = threading.Lock()
_fernet: Optional[Fernet] = None


class CredentialUnreadable(ValueError):
    """A stored credential can't be decrypted with this install's key."""


def _key_path() -> str:
    from app.config import get_settings
    return os.path.join(get_settings().data_dir, KEY_FILE)


def _load() -> Fernet:
    global _fernet
    if _fernet is None:
        with _lock:
            if _fernet is None:
                path = _key_path()
                if not os.path.exists(path):
                    try:
                        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "wb") as f:
                            f.write(Fernet.generate_key())
                        logger.info("Created %s: the key that encrypts stored credentials. Back it up with data/.", path)
                    except FileExistsError:
                        pass                      # another worker made it first
                with open(path, "rb") as f:
                    _fernet = Fernet(f.read().strip())
    return _fernet


def is_sealed(value) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def seal(value):
    """Encrypt a credential for storage. Empty values and values already encrypted pass through."""
    if not value or not isinstance(value, str) or is_sealed(value):
        return value
    return PREFIX + _load().encrypt(value.encode()).decode()


def reveal(value):
    """The plain credential. A value stored before encryption is returned as it is. Raises
    CredentialUnreadable if it was encrypted with a different key (data/credentials.key lost or
    replaced)."""
    if not is_sealed(value):
        return value
    try:
        return _load().decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken as exc:
        raise CredentialUnreadable(
            "A stored credential can't be decrypted: data/credentials.key isn't the key it was "
            "saved with. Enter the credential again.") from exc


def reveal_or_none(value):
    """reveal(), but None (logged) when the value can't be decrypted, so one unreadable credential
    makes that integration fail its connection test instead of breaking the page."""
    try:
        return reveal(value)
    except CredentialUnreadable as exc:
        logger.error(str(exc))
        return None


def reveal_fields(row: Optional[dict], *fields: str) -> Optional[dict]:
    """``row`` with each of ``fields`` decrypted in place (missing fields are skipped)."""
    if row:
        for f in fields:
            if f in row:
                row[f] = reveal_or_none(row[f])
    return row
