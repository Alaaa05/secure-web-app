import sqlite3

DB_NAME = "database.db"

# False = vulnerable version, True = fixed version
# we keep both so we can show the attack before and after in the report
SECURE_MODE = True


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


# finds the user by username only, because bcrypt adds a random salt
# so the stored hash can't be compared inside the SQL query
def find_user(username):
    conn = get_connection()
    if SECURE_MODE:
        # fixed: the input can't change the query
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    else:
        # VULNERABLE: the input goes straight into the SQL string
        query = f"SELECT * FROM users WHERE username = '{username}'"
        user = conn.execute(query).fetchone()
    conn.close()
    return user

# ---------------- Task 3: comments and admin queries ----------------
# These always use ? placeholders. The SQL injection demo is only for
# login and register (SECURE_MODE above), so the new pages stay safe.

def add_comment(user_id, content):
    conn = get_connection()
    conn.execute(
        "INSERT INTO comments (user_id, content) VALUES (?, ?)",
        (user_id, content),
    )
    conn.commit()
    conn.close()


def get_comments():
    # newest first, with the author's username
    conn = get_connection()
    rows = conn.execute(
        """SELECT comments.id, comments.content, comments.created_at, users.username
           FROM comments JOIN users ON comments.user_id = users.id
           ORDER BY comments.id DESC"""
    ).fetchall()
    conn.close()
    return rows


def count_user_comments(user_id):
    conn = get_connection()
    count = conn.execute(
        "SELECT COUNT(*) FROM comments WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    conn.close()
    return count


def delete_comment(comment_id):
    conn = get_connection()
    conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()


def get_all_users():
    # used only by the admin page; we never select the password column
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, username, role FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return rows
