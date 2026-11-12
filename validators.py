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