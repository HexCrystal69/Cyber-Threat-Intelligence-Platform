import logging
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.rag_engine import RAGEngine

logger = logging.getLogger(__name__)

@celery_app.task
def build_embeddings(doc_id: int):
    return {"status": "SUCCESS", "document_id": doc_id}

@celery_app.task
def reindex_documents():
    db = SessionLocal()
    try:
        engine = RAGEngine(db)
        db.close()
        return {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"reindex_documents failed: {e}")
        db.close()
        raise

@celery_app.task
def refresh_vector_store():
    return {"status": "SUCCESS"}
