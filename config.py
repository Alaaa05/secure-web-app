# Switches for the Task 3 and Task 4 security fixes.
# True  = fixed (secure) version
# False = vulnerable version, used only to show the attack in the report
# (SQL injection has its own switch, SECURE_MODE in db.py)

# Task 3 - Access control: False lets anyone open /admin
RBAC_SECURE = True

# Task 3 - XSS: False shows comments as raw HTML, so scripts in them run
XSS_SECURE = True

# Task 4 - Session encryption: False uses Flask's default cookie,
# which is signed but readable by anyone who base64-decodes it
SESSION_ENCRYPTED = True

# Task 4 - HTTPS: False runs the app over plain HTTP
HTTPS_ENABLED = True

# the self-signed certificate and key used for HTTPS (created by generate_cert.py)
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# how long a login lasts without activity, in minutes
SESSION_MINUTES = 30
