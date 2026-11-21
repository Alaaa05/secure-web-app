# Task 4 - Session cookie test: can someone read or change the cookie?
# Run:  python test_session.py

import base64
import json
import zlib

from flask.sessions import SecureCookieSessionInterface

from app import app
from security import EncryptedSessionInterface, get_session_encryption_key
from test_helpers import fresh_database, client, login, show

fresh_database()


def get_cookie(c):
    cookie = c.get_cookie("session")
    return cookie.value if cookie else None


def try_to_read(value):
    # what an attacker would do: base64-decode the first part of the cookie
    try:
        data = value.split(".")[0] if not value.startswith(".") else value.split(".")[1]
        raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
        if value.startswith("."):
            raw = zlib.decompress(raw)  # Flask compresses big cookies
        return json.loads(raw)
    except Exception:
        return None


for encrypted in (False, True):
    app.session_interface = (EncryptedSessionInterface(get_session_encryption_key())
                             if encrypted else SecureCookieSessionInterface())
    print("=" * 60)
    print("SESSION_ENCRYPTED =", encrypted, "(fixed)" if encrypted else "(vulnerable)")
    print("=" * 60)

    c = client()
    r = login(c, "sara", "Sara@1234")
    value = get_cookie(c)
    print("Cookie value:", value[:70] + "...\n")

    decoded = try_to_read(value)
    show("Attacker base64-decodes the session cookie",
         "can't read anything", f"read {decoded}" if decoded else "unreadable",
         decoded is None)

    header = r.headers.get("Set-Cookie", "")
    show("Cookie flags", "HttpOnly; Secure; SameSite=Lax",
         "; ".join(f for f in ("HttpOnly", "Secure", "SameSite=Lax") if f in header),
         all(f in header for f in ("HttpOnly", "Secure", "SameSite=Lax")))

    # change one character in the cookie and use it
    tampered = value[:-5] + ("A" if value[-5] != "A" else "B") + value[-4:]
    c.set_cookie("session", tampered, domain="localhost")
    r = c.get("/dashboard")
    show("Edited (tampered) cookie is sent to /dashboard",
         "rejected, redirect to /login", f"status {r.status_code} -> {r.headers.get('Location')}",
         r.status_code == 302)
