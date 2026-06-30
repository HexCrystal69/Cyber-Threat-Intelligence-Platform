import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, ForeignKey
from src.database import Base

class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"

    id = Column(Integer, primary_key=True, index=True)
    document_type = Column(String, nullable=False, index=True)  # ioc, alert, case, campaign, etc.
    source_table = Column(String, nullable=False)
    source_record_id = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    embedding_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class EmbeddingRecord(Base):
    __tablename__ = "embedding_records"

    id = Column(Integer, primary_key=True, index=True)
    vector_store_key = Column(String, unique=True, index=True, nullable=False)
    embedding_model = Column(String, nullable=False)
    dimension = Column(Integer, default=1536)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class RetrievalExecution(Base):
    __tablename__ = "retrieval_executions"

    id = Column(Integer, primary_key=True, index=True)
    query = Column(String, nullable=False)
    documents_retrieved = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class RetrievedEvidence(Base):
    __tablename__ = "retrieved_evidences"

    id = Column(Integer, primary_key=True, index=True)
    retrieval_execution_id = Column(Integer, ForeignKey("retrieval_executions.id"), nullable=False)
    document_id = Column(Integer, ForeignKey("knowledge_documents.id"), nullable=False)
    similarity_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
