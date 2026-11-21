# Secure Web App

## Project Overview
A user management web app built with Flask and SQLite. Users can create an account, log in, see a dashboard and log out.

The app was first built with common security vulnerabilities on purpose, including SQL injection, weak password storage, XSS and broken access control. Each one was then fixed. The sections below explain how to test each fix.

## Setup and Running the Application
1. `pip install -r requirements.txt`
2. `python init_db.py`
3. `python app.py`
4. Open https://127.0.0.1:5000 (the browser warns about the certificate, click Advanced then Proceed)
   
## Testing SQL Injection (Task 1)
The register and login queries in db.py used to paste the user's input straight into the SQL. Typing `admin' --` as a username changes the query: the quote ends the string and `--` turns the rest into a comment, so the database returns the admin account. The fix uses `?` placeholders, so the input is always treated as plain data and can't change the query.

Run `python test_sqli.py`. It looks up the username `admin' --` on both versions. The vulnerable version returns the admin account. The fixed version finds no user.

To switch versions, set `SECURE_MODE` at the top of db.py (`False` = vulnerable, `True` = fixed).

Password rules: run `python test_password.py`. A password needs at least 8 characters, an uppercase letter, a lowercase letter, a number and a special character. The test checks three weak passwords and one valid one.

## Testing Authentication (Task 2)
The admin account is for testing only (admin / Admin@123) and requires running init_db.py first to create the database.

**Register:** Open /register. Enter a weak password (e.g. abc) and submit — the page returns a message listing the rules it breaks. Then enter a strong password (e.g. Strong@123) and submit — the page shows "Registered successfully".

**Login:** Go to /login and sign in with an existing account using the correct password — you are redirected to / (the home page). Then try the same username with a wrong password — the page returns "Wrong username or password".

**Logout:** While logged in, click the Logout link on the home page — you are redirected to /login.

**Back button:** After logout, press the browser Back button — you should not see the old home page; the browser re-requests /, and the session check redirects you to /login.

**Direct URL:** After logout, type / in the address bar and open it — you are redirected to /login because the session no longer contains username.

## Testing Access Control and Dashboard (Task 3)
<!-- student 3 -->
Each fix can be switched in config.py (True = fixed, False = vulnerable). Restart the app after changing a switch. Use admin / Admin@123 for the admin account, and register a normal account (e.g. sara / Sara@1234) for the user tests.

**Dashboard:** Log in with any account — you are redirected to /dashboard, which shows your user ID, username, role, number of comments, connection type and session timeout.

**Admin access (as admin):** Log in as admin and click "Admin page" — /admin opens and lists all users and comments, with a Delete button for each comment.

**Admin access (as normal user):** Log in as sara and type /admin in the address bar — the page returns "403 Access denied". The "Admin page" link is also hidden for normal users.

**Admin access (not logged in):** Log out and type /admin in the address bar — you are redirected to /login.

**RBAC vulnerable version:** Set RBAC_SECURE = False and restart — /admin now opens for sara and even without logging in, showing that the page had no access check.

**XSS:** On the dashboard, post the comment <img src=x onerror="alert('XSS')"> — no alert appears; the tag is removed and the comment is rejected because it contains only HTML. Post Hi <script>alert('XSS')</script> there — it is saved as plain text "Hi alert('XSS') there" and nothing runs.

**XSS vulnerable version:** Set XSS_SECURE = False and restart, then post the same <img> comment — an alert box appears for every user who opens the dashboard or the admin page (stored XSS).

**Automatic tests:** Run python test_access_control.py and python test_xss.py — each check prints SECURE or VULNERABLE for both versions.

## Testing XSS and Encryption (Task 4)
<!-- student 4 -->
The app runs on https://127.0.0.1:5000. On the first run, app.py creates a self-signed certificate (cert.pem, key.pem) and the secret keys (secret.key, session.key); all of them are in .gitignore and are never pushed to GitHub.

**HTTPS:** Run python app.py and open https://127.0.0.1:5000 — the browser warns that the certificate is self-signed; click Advanced then Proceed. Click the "Not secure" label then the certificate — it is issued to localhost and the connection uses TLS. Opening http://127.0.0.1:5000 does not work because the server only accepts HTTPS.

**Encrypted session cookie:** Log in, open DevTools (Cmd+Option+I) then Application then Cookies — the session cookie starts with gAAAAA (a Fernet token) and can't be read by decoding it.

**Cookie flags:** In the same DevTools view — the session cookie has HttpOnly and Secure ticked, and SameSite is Lax.

**Tampered cookie:** Change one character in the session cookie value and reload the page — you are redirected to /login because the cookie no longer decrypts.

**Session timeout:** Stay inactive for 30 minutes and reload the dashboard — you are redirected to /login.

**Vulnerable version:** Set SESSION_ENCRYPTED = False and restart, then log in again — the cookie starts with eyJ, and base64-decoding the part before the first "." shows {"username": "..."} in plain text.

**Automatic test:** Run python test_session.py — it shows the cookie in both versions, tries to decode it, checks the flags, and sends a tampered cookie.
