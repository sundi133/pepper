"""Evaluation fixture (eval/truth/logic-lab.json). Not a real application."""
import functools

import jwt
from flask import abort, current_app, g, request

from models import ApiClient, User


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        try:
            claims = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.InvalidTokenError:
            abort(401)
        g.user = User.query.get(claims["sub"])
        if g.user is None:
            abort(401)
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not g.user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapper


def api_key_required(view):
    """Partner integrations authenticate with an API key."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        try:
            client = ApiClient.query.filter_by(key=request.headers["X-Api-Key"]).one()
            g.api_client = client
        except Exception:
            current_app.logger.warning("API key lookup failed")
            g.api_client = None
        return view(*args, **kwargs)

    return wrapper
