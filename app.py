import os
from datetime import timedelta

import bcrypt
from flask import Flask, render_template, request, session, redirect, url_for, flash

import config
from db import find_user, add_user, add_comment, get_comments, count_user_comments, \
    delete_comment, get_all_users
from validators import check_password, sanitize_comment
from auth import login_required, role_required
from security import get_secret_key, get_session_encryption_key, EncryptedSessionInterface

app = Flask(__name__)

# ---------------- Task 4: keys, encrypted session, cookie settings ----------------

# a long random key kept outside the code (see security.py),
# replacing the old hard-coded "dev-key"
app.secret_key = get_secret_key()

if config.SESSION_ENCRYPTED:
    # the session cookie is encrypted with Fernet (AES + HMAC), not just signed
    app.session_interface = EncryptedSessionInterface(get_session_encryption_key())

app.config.update(
    # JavaScript can't read the cookie, so an XSS script can't steal it
    SESSION_COOKIE_HTTPONLY=True,
    # the browser sends the cookie only over HTTPS, never over plain HTTP
    SESSION_COOKIE_SECURE=config.HTTPS_ENABLED,
    # the cookie isn't sent with forms posted from other websites (helps against CSRF)
    SESSION_COOKIE_SAMESITE="Lax",
    # the login expires after this much time without activity
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=config.SESSION_MINUTES),
)


# these headers stop the browser from caching pages,
# so after logout the Back button can't show an old copy of a protected page
@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.after_request
def add_security_headers(response):
    # stops other sites from showing our pages inside a frame (clickjacking)
    response.headers["X-Frame-Options"] = "DENY"
    # the browser must trust our Content-Type and not guess it
    response.headers["X-Content-Type-Options"] = "nosniff"
    if config.XSS_SECURE:
        # Task 3: Content Security Policy, a second layer against XSS.
        # Only scripts and styles from our own server may run, so an inline
        # <script> or onerror="..." that slips into a page is blocked.
        # (left off in the vulnerable version, or it would block the demo)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; form-action 'self'; frame-ancestors 'none'"
        )
    if config.HTTPS_ENABLED:
        # Task 4: HSTS tells the browser to use only HTTPS for this site
        response.headers["Strict-Transport-Security"] = "max-age=3600"
    return response


# ---------------- Task 2: register, login, logout ----------------

@app.route("/")
def home():
    # only logged-in users can see this page
    if "username" not in session:
        return redirect(url_for("login"))
    # Task 3: the home page is now the dashboard
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # we fetch the user by username first, then check the password in Python,
        # so the password check no longer happens inside the SQL query
        user = find_user(username)
        if user:
            # checkpw compares the typed password with the stored hash,
            # the original password is never stored; try/except catches ValueError
            # when the stored hash is not bcrypt (e.g. an old MD5 account)
            try:
                if bcrypt.checkpw(password.encode(), user["password"].encode()):
                    # Task 4: start from an empty session so nothing from before
                    # the login is carried over (protects against session fixation)
                    session.clear()
                    session["username"] = username
                    # Task 4: use PERMANENT_SESSION_LIFETIME, so the login expires
                    session.permanent = True
                    return redirect(url_for("home"))
            except ValueError:
                pass
        return "Wrong username or password"
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        problems = check_password(password)
        if problems:
            return "Password does not meet the requirements: " + ", ".join(problems)
        # bcrypt is slower than MD5 on purpose, which makes brute-force harder;
        # gensalt() adds a random salt so identical passwords get different hashes
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        add_user(username, password_hash)
        return "Registered successfully"
    return render_template("register.html")


@app.route("/logout")
def logout():
    # empties the session data (removes username) and updates the
    # session cookie; by default Flask stores the session client-side
    session.clear()
    return redirect(url_for("login"))


# ---------------- Task 3: dashboard, comments (XSS), admin page (RBAC) ----------------

@app.route("/dashboard")
@login_required
def dashboard():
    user = find_user(session["username"])
    if user is None:
        # the account was deleted while the user was logged in
        session.clear()
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        user=user,
        comment_count=count_user_comments(user["id"]),
        comments=get_comments(),
        xss_secure=config.XSS_SECURE,
        is_https=request.is_secure,
        session_minutes=config.SESSION_MINUTES,
    )


@app.route("/comment", methods=["POST"])
@login_required
def post_comment():
    user = find_user(session["username"])
    text = request.form.get("content", "")
    if config.XSS_SECURE:
        # FIXED: clean the input before saving it (see validators.py)
        text, error = sanitize_comment(text)
        if error:
            flash(error)
            return redirect(url_for("dashboard"))
    else:
        # VULNERABLE: the comment is saved exactly as typed, HTML included
        if not text.strip():
            return redirect(url_for("dashboard"))
    add_comment(user["id"], text)
    return redirect(url_for("dashboard"))


@app.route("/admin")
@role_required("admin")
def admin():
    return render_template(
        "admin.html",
        users=get_all_users(),
        comments=get_comments(),
        xss_secure=config.XSS_SECURE,
        rbac_secure=config.RBAC_SECURE,
    )


@app.route("/admin/delete_comment/<int:comment_id>", methods=["POST"])
@role_required("admin")
def admin_delete_comment(comment_id):
    # POST, not GET, so a simple link or <img> on another page can't delete comments
    delete_comment(comment_id)
    return redirect(url_for("admin"))


@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html"), 403


if __name__ == "__main__":
    if config.HTTPS_ENABLED:
        # Task 4: run over HTTPS (TLS). The certificate is created once if missing.
        if not (os.path.exists(config.CERT_FILE) and os.path.exists(config.KEY_FILE)):
            from generate_cert import generate
            generate()
        print("Open https://127.0.0.1:5000  (accept the self-signed certificate warning)")
        # debug=True shows errors in the browser while we're building
        app.run(debug=True, ssl_context=(config.CERT_FILE, config.KEY_FILE))
    else:
        app.run(debug=True)
