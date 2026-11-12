import sqlite3

DB_NAME = "database.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    # lets us read columns by name, like user["role"]
    conn.row_factory = sqlite3.Row
    return conn


def add_user(username, password_hash, role="user"):
    conn = get_connection()
    # VULNERABLE: the input goes straight into the SQL string, fixed later
    query = f"INSERT INTO users (username, password, role) VALUES ('{username}', '{password_hash}', '{role}')"
    conn.execute(query)
    conn.commit()
    conn.close()


def find_user(username, password_hash):
    conn = get_connection()
    # VULNERABLE: typing  admin' --  as the username skips the password check
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
    user = conn.execute(query).fetchone()
    conn.close()
    return user