import datetime
import uuid
from sqlalchemy.orm import Session
from src.models.rag import KnowledgeDocument, EmbeddingRecord, RetrievalExecution, RetrievedEvidence
from src.utils.metrics import documents_embedded_total, rag_queries_total

class RAGEngine:
    def __init__(self, db: Session):
        self.db = db

    def ingest_document(self, doc_type: str, source_table: str, source_record_id: str, content: str) -> KnowledgeDocument:
        vector_key = f"vec-{uuid.uuid4()}"
        emb = EmbeddingRecord(
            vector_store_key=vector_key,
            embedding_model="text-embedding-3-small",
            dimension=1536,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(emb)
        self.db.commit()
        self.db.refresh(emb)

        doc = KnowledgeDocument(
            document_type=doc_type,
            source_table=source_table,
            source_record_id=source_record_id,
            content=content,
            embedding_id=emb.id,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(doc)
        self.db.commit()
        self.db.refresh(doc)
        documents_embedded_total.inc()
        return doc

    def retrieve_relevant_evidence(self, query: str, limit: int = 3) -> list:
        start_time = datetime.datetime.utcnow()
        docs = self.db.query(KnowledgeDocument).all()
        
        matches = []
        words = query.lower().split()
        for doc in docs:
            score = 0.0
            for w in words:
                if w in doc.content.lower():
                    score += 0.35
            if score > 0.0:
                matches.append((doc, min(1.0, score)))

        matches.sort(key=lambda x: x[1], reverse=True)
        top_matches = matches[:limit]

        duration = int((datetime.datetime.utcnow() - start_time).total_seconds() * 1000)
        exec_record = RetrievalExecution(
            query=query,
            documents_retrieved=len(top_matches),
            latency_ms=max(1, duration),
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(exec_record)
        self.db.commit()
        self.db.refresh(exec_record)

        results = []
        for doc, score in top_matches:
            ev = RetrievedEvidence(
                retrieval_execution_id=exec_record.id,
                document_id=doc.id,
                similarity_score=score,
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(ev)
            results.append({"document": doc, "similarity_score": score})

        self.db.commit()
        rag_queries_total.inc()
        return results
