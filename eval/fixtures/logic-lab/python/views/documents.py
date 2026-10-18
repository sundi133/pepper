from flask import Blueprint, g, jsonify, request

from auth import api_key_required, login_required
from models import Document, db
from tasks import reindex_document

bp = Blueprint("documents", __name__)


@bp.route("/documents", methods=["POST"])
@login_required
def create_document():
    doc = Document(title=request.json["title"], body=request.json["body"], owner_id=g.user.id)
    db.session.add(doc)
    db.session.commit()
    return jsonify(doc.to_dict()), 201


@bp.route("/documents/<int:doc_id>", methods=["GET"])
@login_required
def get_document(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=g.user.id).first_or_404()
    return jsonify(doc.to_dict())


@bp.route("/documents/<int:doc_id>", methods=["PATCH"])
@login_required
def update_document(doc_id):
    doc = Document.query.filter_by(id=doc_id).first_or_404()
    doc.title = request.json.get("title", doc.title)
    doc.body = request.json.get("body", doc.body)
    db.session.commit()
    return jsonify(doc.to_dict())


@bp.route("/documents/<int:doc_id>/reindex", methods=["POST"])
@login_required
def reindex(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=g.user.id).first_or_404()
    reindex_document.delay(doc.id)
    return jsonify({"queued": True}), 202


@bp.route("/partner/documents", methods=["GET"])
@api_key_required
def partner_documents():
    docs = Document.query.filter_by(shared_with_partners=True).all()
    return jsonify([d.to_dict() for d in docs])
