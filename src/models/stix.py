import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from src.database import Base

class STIXBundle(Base):
    __tablename__ = "stix_bundles"

    id = Column(Integer, primary_key=True, index=True)
    bundle_id = Column(String, unique=True, index=True)
    object_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class STIXObject(Base):
    __tablename__ = "stix_objects"

    id = Column(Integer, primary_key=True, index=True)
    bundle_id = Column(String, ForeignKey("stix_bundles.bundle_id"), nullable=True)
    object_type = Column(String, nullable=False, index=True)
    object_identifier = Column(String, unique=True, index=True)
    object_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class STIXRelationship(Base):
    __tablename__ = "stix_relationships"

    id = Column(Integer, primary_key=True, index=True)
    source_object_id = Column(String, nullable=False, index=True)
    target_object_id = Column(String, nullable=False, index=True)
    relationship_type = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class STIXGraph(Base):
    __tablename__ = "stix_graphs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
