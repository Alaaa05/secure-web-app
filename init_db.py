import sqlite3
import hashlib

conn = sqlite3.connect("database.db")
cur = conn.cursor()

# users table, everyone is "user" unless we set them as "admin"
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
)
""")

# comments table, used later for the XSS part (Task 3)
cur.execute("""
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

# one admin account so Task 3 can test the admin page
# MD5 is weak on purpose here, Task 2 moves passwords to bcrypt later
admin_pw = hashlib.md5("Admin@123".encode()).hexdigest()
cur.execute(
    "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
    ("admin", admin_pw, "admin"),
)

conn.commit()
conn.close()
print("Database ready")