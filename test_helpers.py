# Shared setup for the Task 3 / Task 4 test scripts.
# Every test uses a brand-new temporary database, so your real database.db is never touched.

import os
import subprocess
import sys
import tempfile

import bcrypt

import db

HERE = os.path.dirname(os.path.abspath(__file__))


def fresh_database():
    # runs init_db.py inside an empty temp folder -> users + comments tables + admin account
    folder = tempfile.mkdtemp()
    subprocess.run([sys.executable, os.path.join(HERE, "init_db.py")], cwd=folder,
                   check=True, stdout=subprocess.DEVNULL)
    db.DB_NAME = os.path.join(folder, "database.db")
    # a normal user for the tests (password follows the Task 1 rules)
    db.SECURE_MODE = True
    db.add_user("sara", bcrypt.hashpw(b"Sara@1234", bcrypt.gensalt()).decode())


def client():
    from app import app
    app.config["TESTING"] = True
    c = app.test_client()
    # pretend every request comes over HTTPS, because the cookie has the Secure flag
    c.environ_base["wsgi.url_scheme"] = "https"
    return c


def login(c, username, password):
    return c.post("/login", data={"username": username, "password": password})


def show(test_name, expected, actual, secure):
    # SECURE = we got the expected secure result, VULNERABLE = the attack worked
    print(f"[{'SECURE' if secure else 'VULNERABLE'}] {test_name}")
    print(f"       expected: {expected}")
    print(f"       actual:   {actual}\n")
