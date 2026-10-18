from flask import Blueprint, jsonify

from auth import admin_required, login_required
from models import Document, User, db

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/stats")
@login_required
@admin_required
def stats():
    return jsonify({"users": User.query.count(), "documents": Document.query.count()})


@bp.route("/users/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return "", 204
