"""``gdown login | logout | whoami``: manage the encrypted cookie store.

You sign in to Google yourself, in your own browser, and hand gdown the
resulting cookies once: as an exported cookies.txt / JSON file, straight from
a desktop browser profile, or pasted on stdin. They are sealed at once and
never written in plain text by gdown.
"""

import argparse
import json
import os
import re
import secrets
import sys
from http.cookiejar import Cookie

import requests

from . import _vault

_ACCOUNTS_URL = (
    "https://accounts.google.com/ListAccounts?gpsia=1&source=ChromiumBrowser&json=standard"
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _parse_netscape(text: str) -> list[Cookie]:
    cookies = []
    for line in text.splitlines():
        if line.startswith("#HttpOnly_"):
            line, http_only = line[len("#HttpOnly_") :], True
        elif not line.strip() or line.startswith("#"):
            continue
        else:
            http_only = False
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 7:
            continue
        domain, _, path, secure, expires, name, value = parts
        cookies.append(
            _vault.make_cookie(
                name=name,
                value=value,
                domain=domain,
                path=path,
                secure=secure.upper() == "TRUE",
                expires=int(expires) if expires.isdigit() and int(expires) else None,
                http_only=http_only,
            )
        )
    return cookies


def _parse_json(text: str) -> list[Cookie]:
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("cookies", [])
    cookies = []
    for d in data:
        expires = d.get("expirationDate", d.get("expires"))
        if d.get("session"):
            expires = None
        domain = d["domain"]
        if not d.get("hostOnly", False) and not domain.startswith("."):
            domain = "." + domain
        cookies.append(
            _vault.make_cookie(
                name=d["name"],
                value=d["value"],
                domain=domain,
                path=d.get("path", "/"),
                secure=bool(d.get("secure", True)),
                expires=expires if expires and expires > 0 else None,
                http_only=bool(d.get("httpOnly", False)),
            )
        )
    return cookies


def _parse_header(text: str) -> list[Cookie]:
    text = re.sub(r"^\s*cookie:\s*", "", text.strip(), flags=re.IGNORECASE)
    cookies = []
    for pair in text.split(";"):
        if "=" not in pair:
            continue
        name, value = pair.strip().split("=", 1)
        cookies.append(_vault.make_cookie(name=name, value=value, domain=".google.com"))
    return cookies


def parse_cookies(text: str) -> list[Cookie]:
    stripped = text.lstrip()
    if stripped.startswith(("[", "{")):
        cookies = _parse_json(stripped)
    elif "\t" in text:
        cookies = _parse_netscape(text)
    else:
        cookies = _parse_header(text)
    return [c for c in cookies if _vault.is_google(c.domain)]


def _shred(path: str) -> None:
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.write(secrets.token_bytes(size))
        f.flush()
        os.fsync(f.fileno())
    os.unlink(path)


def signed_in_accounts(cookies: list[Cookie]) -> list[str]:
    sess = requests.session()
    for c in cookies:
        sess.cookies.set_cookie(c)
    res = sess.post(_ACCOUNTS_URL, timeout=20)
    res.raise_for_status()
    return sorted(set(_EMAIL.findall(res.text)))


def _login(args: argparse.Namespace) -> int:
    if args.from_browser:
        from ._vendor._ytdlp_cookies import extract_cookies_from_browser  # noqa: PLC0415

        cookies = [
            c
            for c in extract_cookies_from_browser(args.from_browser)
            if _vault.is_google(c.domain)
        ]
    elif args.from_file:
        with open(os.path.expanduser(args.from_file), encoding="utf-8") as f:
            cookies = parse_cookies(f.read())
    else:
        if sys.stdin.isatty():
            print(
                "Paste Google cookies (cookies.txt, JSON export or a Cookie: header),"
                " then Ctrl-D:",
                file=sys.stderr,
            )
        cookies = parse_cookies(sys.stdin.read())
    if not cookies:
        print("No google.com cookies found in that input.", file=sys.stderr)
        return 1

    accounts = [] if args.no_check else signed_in_accounts(cookies)
    if not args.no_check and not accounts:
        print(
            "These cookies are not signed in to any Google account; nothing saved.",
            file=sys.stderr,
        )
        return 1

    mode = _vault.MODE_PASSPHRASE if args.passphrase else _vault.MODE_KEYFILE
    if _vault.exists():
        _vault.erase()
    n = _vault.save(cookies, mode=mode)
    where = "passphrase" if args.passphrase else f"key file {_vault.KEY_FILE}"
    print(f"Sealed {n} cookies in {_vault.STORE_FILE} ({where}).", file=sys.stderr)
    for email in accounts:
        print(f"Signed in as {email}", file=sys.stderr)
    if args.from_file and args.shred:
        _shred(os.path.expanduser(args.from_file))
        print(f"Overwrote and removed {args.from_file}.", file=sys.stderr)
    elif args.from_file:
        print(
            f"{args.from_file} still holds the cookies in plain text; "
            "delete it or rerun with --shred.",
            file=sys.stderr,
        )
    return 0


def _logout(args: argparse.Namespace) -> int:
    removed = _vault.erase()
    if args.forget_key and os.path.exists(_vault.KEY_FILE):
        _vault.erase(_vault.KEY_FILE)
    print("Cookie store erased." if removed else "No cookie store.", file=sys.stderr)
    return 0


def _whoami(_: argparse.Namespace) -> int:
    if not _vault.exists():
        print("Not logged in (no cookie store).", file=sys.stderr)
        return 1
    accounts = signed_in_accounts(_vault.load())
    if not accounts:
        print("The stored session is no longer signed in; run `gdown login`.")
        return 1
    for email in accounts:
        print(email)
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="gdown")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("login", help="seal a Google session into the cookie store")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--from-file", metavar="FILE", help="cookies.txt or JSON export")
    src.add_argument("--from-browser", metavar="BROWSER", help="desktop browser profile")
    p.add_argument(
        "--passphrase",
        action="store_true",
        help=f"lock with a passphrase (asked, or ${_vault.PASSPHRASE_ENV}) "
        "instead of a key file",
    )
    p.add_argument("--shred", action="store_true", help="overwrite and delete FILE")
    p.add_argument(
        "--no-check", action="store_true", help="skip the signed-in check (offline)"
    )
    p.set_defaults(func=_login)

    p = sub.add_parser("logout", help="erase the cookie store")
    p.add_argument("--forget-key", action="store_true", help="erase the key file too")
    p.set_defaults(func=_logout)

    p = sub.add_parser("whoami", help="show the account the store is signed in as")
    p.set_defaults(func=_whoami)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except _vault.VaultError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
