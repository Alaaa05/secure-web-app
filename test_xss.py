# Task 3 - XSS test: a comment with HTML/JavaScript, before and after the fix.
# Run:  python test_xss.py

import config
from test_helpers import fresh_database, client, login, show

ATTACK = '<img src=x onerror="alert(\'XSS\')">'

for secure in (False, True):
    fresh_database()
    config.XSS_SECURE = secure
    print("=" * 60)
    print("XSS_SECURE =", secure, "(fixed)" if secure else "(vulnerable)")
    print("=" * 60)

    c = client()
    login(c, "sara", "Sara@1234")
    c.post("/comment", data={"content": ATTACK})
    r = c.get("/dashboard")
    page = r.get_data(as_text=True)

    script_in_page = 'onerror="alert' in page
    show("Post comment " + ATTACK,
         "the tag is removed / shown as text, no script in the page",
         "raw <img onerror> is in the page, the script runs" if script_in_page
         else "no executable tag in the page",
         not script_in_page)

    csp = r.headers.get("Content-Security-Policy")
    show("Content-Security-Policy header", "present", csp or "missing",
         bool(csp))

    # a comment saved while the app was vulnerable must still be harmless after the fix
    if secure:
        import db
        db.add_comment(2, "<script>alert(1)</script>")  # saved directly, skipping sanitize
        page = c.get("/dashboard").get_data(as_text=True)
        show("Old malicious comment already in the database",
             "escaped by Jinja2 as &lt;script&gt;",
             "escaped" if "&lt;script&gt;" in page else "raw <script> in page",
             "&lt;script&gt;" in page)
