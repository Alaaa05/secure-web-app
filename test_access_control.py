# Task 3 - RBAC test: who can open /admin, before and after the fix.
# Run:  python test_access_control.py

import config
from test_helpers import fresh_database, client, login, show

fresh_database()

for secure in (False, True):
    config.RBAC_SECURE = secure
    print("=" * 60)
    print("RBAC_SECURE =", secure, "(fixed)" if secure else "(vulnerable)")
    print("=" * 60)

    c = client()
    r = c.get("/admin")
    show("Not logged in opens /admin",
         "redirect to /login (302)", f"status {r.status_code}",
         (r.status_code == 302))

    c = client()
    login(c, "sara", "Sara@1234")
    r = c.get("/admin")
    show("Standard user (sara) opens /admin",
         "403 Forbidden", f"status {r.status_code}",
         (r.status_code == 403))

    r = c.post("/admin/delete_comment/1")
    show("Standard user sends a delete-comment request",
         "403 Forbidden", f"status {r.status_code}",
         (r.status_code == 403))

    c = client()
    login(c, "admin", "Admin@123")
    r = c.get("/admin")
    show("Admin opens /admin", "200 OK, user list shown", f"status {r.status_code}",
         r.status_code == 200)
