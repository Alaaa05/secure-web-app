# Task 3 - Access control (RBAC) helpers.
#
# Instead of repeating "if username not in session" in every route, we put the
# checks in decorators. A route that needs a login or a role just adds one line
# above it, so it is hard to forget a check when we add new pages.

from functools import wraps

from flask import session, redirect, url_for, abort

import config
from db import find_user


def login_required(view):
    # same idea as the / page from Task 2: no username in the session -> login page
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def current_role():
    # We read the role from the database on every request instead of trusting
    # a value saved at login. If an admin is changed back to a normal user,
    # the change works right away, not only after they log in again.
    user = find_user(session.get("username", ""))
    return user["role"] if user else None


def role_required(*allowed_roles):
    # usage:  @role_required("admin")
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not config.RBAC_SECURE:
                # VULNERABLE: no check at all. Anyone who knows the URL,
                # even without logging in, can open the page.
                # (hiding the link on the dashboard does NOT protect the page)
                return view(*args, **kwargs)

            # FIXED: 1) must be logged in  2) must have one of the allowed roles
            if "username" not in session:
                return redirect(url_for("login"))
            if current_role() not in allowed_roles:
                # 403 Forbidden: we know who you are, but you are not allowed here
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator
