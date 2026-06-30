import datetime
from sqlalchemy import Column, Integer, DateTime, JSON
from src.database import Base

class ThreatGraphSnapshot(Base):
    __tablename__ = "threat_graph_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    node_count = Column(Integer, default=0, nullable=False)
    edge_count = Column(Integer, default=0, nullable=False)
    graph_json = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
