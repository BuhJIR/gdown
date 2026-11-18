"""Encrypted cookie store for a signed-in Google session.

The store is one file, ``~/.config/gdown/cookies.enc``. It stays sealed
unless a download is run with ``--vault`` or Drive answers that the file
needs a signed-in account; nothing else ever opens it.

Its plaintext is a JSON list of google.com cookies, sealed with AES-256-GCM.
The key is either a random key file next to the store (``key``, mode 0600)
or a passphrase stretched with scrypt; in passphrase mode nothing that
unlocks the store is written to disk.

Layout: MAGIC (8) | mode (1) | salt (16) | nonce (12) | ciphertext+tag.
Everything before the ciphertext is authenticated as associated data.
"""

import contextlib
import getpass
import hashlib
import json
import os
import os.path as osp
import secrets
import sys
import tempfile
import urllib.parse
from collections.abc import Iterable
from http.cookiejar import Cookie
from typing import Any
from typing import Final

MAGIC: Final = b"GDOWNV1\x00"
MODE_KEYFILE: Final = 0
MODE_PASSPHRASE: Final = 1
CONFIG_DIR: Final = osp.join(osp.expanduser("~"), ".config", "gdown")
STORE_FILE: Final = osp.join(CONFIG_DIR, "cookies.enc")
KEY_FILE: Final = osp.join(CONFIG_DIR, "key")
PASSPHRASE_ENV: Final = "GDOWN_PASSPHRASE"

_HEADER_LEN: Final = len(MAGIC) + 1 + 16 + 12
_SCRYPT: Final = {"n": 2**15, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024, "dklen": 32}


class VaultError(OSError):
    pass


_cached_passphrase: str | None = None


def is_store(path: str) -> bool:
    return path.endswith(".enc")


TRUSTED_HOSTS: Final = ("google.com", "googleusercontent.com", "googleapis.com")


def is_trusted_url(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    return parts.scheme == "https" and any(
        host == h or host.endswith("." + h) for h in TRUSTED_HOSTS
    )


def guard_redirect(response: Any, *args: Any, **kwargs: Any) -> None:
    """Keep a signed-in session on https Google hosts, redirects included."""
    if not is_trusted_url(response.url):
        raise VaultError(f"refusing signed-in request to {response.url}")
    if response.is_redirect:
        target = urllib.parse.urljoin(response.url, response.headers["location"])
        if not is_trusted_url(target):
            response.close()
            raise VaultError(f"refusing signed-in redirect to {target}")


def is_google(domain: str) -> bool:
    return domain in ("google.com", ".google.com") or domain.endswith(".google.com")


def _aesgcm(key: bytes):  # noqa: ANN202
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415
    except ImportError as e:
        raise VaultError("the cookie store needs the 'cryptography' package") from e
    return AESGCM(key)


def _write_private(path: str, data: bytes) -> None:
    directory = osp.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _keyfile_key(*, create: bool) -> bytes:
    if not osp.exists(KEY_FILE):
        if not create:
            raise VaultError(f"key file {KEY_FILE} is missing; run `gdown login`")
        _write_private(KEY_FILE, secrets.token_hex(32).encode() + b"\n")
    if os.stat(KEY_FILE).st_mode & 0o077:
        raise VaultError(f"{KEY_FILE} is open to other users; chmod 600 it")
    with open(KEY_FILE, "rb") as f:
        raw = f.read().strip()
    try:
        key = bytes.fromhex(raw.decode())
    except ValueError as e:
        raise VaultError(f"{KEY_FILE} is not a hex key") from e
    if len(key) != 32:
        raise VaultError(f"{KEY_FILE} must hold 32 bytes")
    return key


def _passphrase(*, confirm: bool) -> str:
    global _cached_passphrase  # noqa: PLW0603
    value = os.environ.get(PASSPHRASE_ENV) or _cached_passphrase
    if value:
        return value
    if not sys.stdin.isatty():
        raise VaultError(f"passphrase needed: set {PASSPHRASE_ENV} or use a terminal")
    value = getpass.getpass("gdown passphrase: ")
    if not value:
        raise VaultError("empty passphrase")
    if confirm and getpass.getpass("repeat passphrase: ") != value:
        raise VaultError("passphrases differ")
    _cached_passphrase = value
    return value


def _derive(*, mode: int, salt: bytes, create: bool) -> bytes:
    if mode == MODE_KEYFILE:
        return _keyfile_key(create=create)
    if mode == MODE_PASSPHRASE:
        return hashlib.scrypt(_passphrase(confirm=create).encode(), salt=salt, **_SCRYPT)
    raise VaultError(f"unknown store mode {mode}")


def make_cookie(
    *,
    name: str,
    value: str,
    domain: str,
    path: str = "/",
    secure: bool = True,
    expires: float | None = None,
    http_only: bool = False,
) -> Cookie:
    exp = int(expires) if expires else None
    return Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=domain.startswith("."),
        domain_initial_dot=domain.startswith("."),
        path=path or "/",
        path_specified=True,
        secure=secure,
        expires=exp,
        discard=exp is None,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": ""} if http_only else {},
    )


def _row(c: Cookie) -> dict:
    return {
        "name": c.name,
        "value": c.value,
        "domain": c.domain,
        "path": c.path,
        "secure": bool(c.secure),
        "expires": c.expires,
        "http_only": c.has_nonstandard_attr("HttpOnly"),
    }


def exists(path: str = STORE_FILE) -> bool:
    return osp.exists(path)


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) <= _HEADER_LEN or blob[: len(MAGIC)] != MAGIC:
        raise VaultError(f"{path} is not a gdown cookie store")
    return blob


def mode_of(path: str = STORE_FILE) -> int | None:
    return _read(path)[len(MAGIC)] if osp.exists(path) else None


def load(path: str = STORE_FILE) -> list[Cookie]:
    if not osp.exists(path):
        raise VaultError(f"no cookie store at {path}; run `gdown login`")
    blob = _read(path)
    mode = blob[len(MAGIC)]
    salt = blob[len(MAGIC) + 1 : len(MAGIC) + 17]
    nonce = blob[len(MAGIC) + 17 : _HEADER_LEN]
    key = _derive(mode=mode, salt=salt, create=False)
    try:
        plain = _aesgcm(key).decrypt(nonce, blob[_HEADER_LEN:], blob[:_HEADER_LEN])
    except Exception as e:
        raise VaultError(f"cannot unlock {path}: wrong key or altered file") from e
    return [make_cookie(**row) for row in json.loads(plain)]


def save(cookies: Iterable[Cookie], path: str = STORE_FILE, *, mode: int | None = None) -> int:
    if mode is None:
        mode = mode_of(path)
    if mode is None:
        mode = MODE_KEYFILE
    rows = {}
    for c in cookies:
        if is_google(c.domain):
            rows[(c.domain, c.path, c.name)] = _row(c)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive(mode=mode, salt=salt, create=True)
    header = MAGIC + bytes([mode]) + salt + nonce
    sealed = _aesgcm(key).encrypt(nonce, json.dumps(list(rows.values())).encode(), header)
    _write_private(path, header + sealed)
    return len(rows)


def erase(path: str = STORE_FILE) -> bool:
    if not osp.exists(path):
        return False
    size = osp.getsize(path)
    with open(path, "r+b") as f:
        f.write(secrets.token_bytes(size))
        f.flush()
        os.fsync(f.fileno())
    os.unlink(path)
    return True
