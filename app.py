import bcrypt
from flask import Flask, render_template, request, session, redirect, url_for
from db import find_user, add_user
from validators import check_password

app = Flask(__name__)

# temporary key for now, Task 4 will replace it with a proper secret key
app.secret_key = "dev-key"

# these headers stop the browser from caching pages,
# so after logout the Back button can't show an old copy of a protected page
@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/")
def home():
    # only logged-in users can see this page
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")

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
                    session["username"] = username
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
    # empties the session data (removes username) and updates the signed
    # session cookie; by default Flask stores the session client-side
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    # debug=True shows errors in the browser while we're building
    app.run(debug=True)