from celery import shared_task

from models import Document, SearchIndex


@shared_task
def reindex_document(doc_id):
    # Queued by the API only after it checked the caller owns the document.
    doc = Document.query.get(doc_id)
    SearchIndex.put(doc.id, doc.title, doc.body)
