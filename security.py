# Task 4 - Encryption helpers: secret keys and the encrypted session cookie.
#
# Flask keeps the session in a cookie on the user's browser. By default that
# cookie is only SIGNED: nobody can change it without the server noticing,
# but anyone can base64-decode it and read what is inside (username, role...).
# Here we ENCRYPT it as well, so the cookie is unreadable without the server key.

import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from flask.json.tag import TaggedJSONSerializer
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import BadSignature


def load_or_create_key(env_name, file_name, make_key):
    # 1) a key set in an environment variable wins (good for a real server)
    # 2) otherwise reuse the key saved in a local file
    # 3) otherwise create a new random key and save it
    # The key files are in .gitignore, so keys never end up on GitHub.
    # (the old  app.secret_key = "dev-key"  was public in the repo, so anyone
    # could have used it to forge a session cookie)
    value = os.environ.get(env_name)
    if value:
        return value.encode()
    if os.path.exists(file_name):
        with open(file_name, "rb") as f:
            return f.read().strip()
    key = make_key()
    with open(file_name, "wb") as f:
        f.write(key)
    return key


def get_secret_key():
    # 32 random bytes from the OS's secure random generator
    return load_or_create_key("SECRET_KEY", "secret.key",
                              lambda: secrets.token_hex(32).encode())


def get_session_encryption_key():
    # Fernet.generate_key() makes a random 32-byte key (base64 encoded)
    return load_or_create_key("SESSION_ENCRYPTION_KEY", "session.key",
                              Fernet.generate_key)


class FernetSerializer:
    # Turns the session dict into an encrypted token and back.
    # Fernet = AES-128 in CBC mode for secrecy + HMAC-SHA256 for integrity,
    # so the cookie can't be read AND can't be changed without the key.
    # We chose Fernet (from the "cryptography" library) instead of writing our
    # own AES code, because hand-made crypto is easy to get wrong.

    def __init__(self, key):
        self.fernet = Fernet(key)
        # Flask's own JSON format, so values like datetimes still work
        self.json = TaggedJSONSerializer()

    def dumps(self, data):
        plain = self.json.dumps(data).encode()
        return self.fernet.encrypt(plain).decode()

    def loads(self, token, max_age=None):
        try:
            # ttl makes old tokens expire even if someone copied the cookie
            plain = self.fernet.decrypt(token.encode(), ttl=max_age)
        except InvalidToken:
            # wrong key, edited cookie, or expired: Flask treats this as
            # "no session", so the user is simply logged out
            raise BadSignature("session cookie could not be decrypted")
        return self.json.loads(plain.decode())


class EncryptedSessionInterface(SecureCookieSessionInterface):
    # Same as Flask's normal cookie session, but the cookie content is
    # encrypted with Fernet instead of only being signed.

    def __init__(self, key):
        self.serializer_obj = FernetSerializer(key)

    def get_signing_serializer(self, app):
        return self.serializer_obj
