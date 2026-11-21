import re

# shown to the user on the register page so they know the rules up front
PASSWORD_RULES = [
    "At least 8 characters",
    "At least one uppercase letter (A-Z)",
    "At least one lowercase letter (a-z)",
    "At least one number (0-9)",
    "At least one special character (like ! @ # $ %)",
]


def check_password(password):
    # returns a list of the rules the password breaks
    # an empty list means the password is fine
    problems = []
    if len(password) < 8:
        problems.append(PASSWORD_RULES[0])
    if not re.search(r"[A-Z]", password):
        problems.append(PASSWORD_RULES[1])
    if not re.search(r"[a-z]", password):
        problems.append(PASSWORD_RULES[2])
    if not re.search(r"[0-9]", password):
        problems.append(PASSWORD_RULES[3])
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append(PASSWORD_RULES[4])
    return problems

# ---------------- Task 3: comment input sanitization (XSS) ----------------
MAX_COMMENT_LENGTH = 500

# matches anything that looks like an HTML tag, e.g. <script> or <img ...>
TAG_PATTERN = re.compile(r"<[^>]*>")


def sanitize_comment(text):
    # Cleans a comment BEFORE it is saved. Returns (clean_text, error).
    # 1) remove extra spaces  2) reject empty or too long comments
    # 3) remove HTML tags, so <script> or <img onerror=...> can't be stored
    # This is the first layer. The second layer is output encoding: Jinja2
    # escapes the comment again when the page is built (see dashboard.html),
    # so even a comment saved while the app was vulnerable can't run.
    text = text.strip()
    if not text:
        return None, "Comment can't be empty"
    if len(text) > MAX_COMMENT_LENGTH:
        return None, f"Comment must be {MAX_COMMENT_LENGTH} characters or less"
    text = TAG_PATTERN.sub("", text).strip()
    if not text:
        return None, "Comment can't contain only HTML"
    return text, None
