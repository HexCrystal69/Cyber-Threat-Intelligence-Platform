import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Text
from src.database import Base

class GraphEntity(Base):
    __tablename__ = "graph_entities"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String, nullable=False, index=True)  # IOC, Campaign, Actor, Case, Alert, Detection
    entity_name = Column(String, nullable=False, index=True)
    source_table = Column(String, nullable=False)
    source_record_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class GraphRelationship(Base):
    __tablename__ = "graph_relationships"

    id = Column(Integer, primary_key=True, index=True)
    source_entity_id = Column(Integer, ForeignKey("graph_entities.id"), nullable=False)
    target_entity_id = Column(Integer, ForeignKey("graph_entities.id"), nullable=False)
    relationship_type = Column(String, nullable=False, index=True)
    weight = Column(Float, default=1.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class GraphSnapshot(Base):
    __tablename__ = "graph_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    node_count = Column(Integer, default=0)
    edge_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class GraphPathCache(Base):
    __tablename__ = "graph_path_caches"

    id = Column(Integer, primary_key=True, index=True)
    source_entity_id = Column(Integer, ForeignKey("graph_entities.id"), nullable=False)
    target_entity_id = Column(Integer, ForeignKey("graph_entities.id"), nullable=False)
    path_json = Column(Text, nullable=False)
    hop_count = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class GraphCommunity(Base):
    __tablename__ = "graph_communities"

    id = Column(Integer, primary_key=True, index=True)
    community_name = Column(String, nullable=False, unique=True)
    entity_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
