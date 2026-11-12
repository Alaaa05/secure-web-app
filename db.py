import sqlite3

DB_NAME = "database.db"

# False = vulnerable version, True = fixed version
# we keep both so we can show the attack before and after in the report
SECURE_MODE = False


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    # lets us read columns by name, like user["role"]
    conn.row_factory = sqlite3.Row
    return conn


def add_user(username, password_hash, role="user"):
    conn = get_connection()
    if SECURE_MODE:
        # fixed: the ? placeholders send the values separately from the SQL,
        # so whatever the user types is treated as data, never as code
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
    else:
        # VULNERABLE: the input goes straight into the SQL string
        query = f"INSERT INTO users (username, password, role) VALUES ('{username}', '{password_hash}', '{role}')"
        conn.execute(query)
    conn.commit()
    conn.close()


def find_user(username, password_hash):
    conn = get_connection()
    if SECURE_MODE:
        # fixed: same idea, the input can't change the query
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password_hash),
        ).fetchone()
    else:
        # VULNERABLE: typing  admin' --  as the username skips the password check
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
        user = conn.execute(query).fetchone()
    conn.close()
    return user