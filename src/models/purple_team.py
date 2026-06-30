import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from src.database import Base

class AttackSimulation(Base):
    __tablename__ = "attack_simulations"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String, nullable=False, index=True)
    simulation_name = Column(String, nullable=False)
    status = Column(String, default="PENDING")  # PENDING, RUNNING, SUCCESS, FAILED
    executed_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class SimulationResult(Base):
    __tablename__ = "simulation_results"

    id = Column(Integer, primary_key=True, index=True)
    simulation_id = Column(Integer, ForeignKey("attack_simulations.id"), nullable=False)
    detection_triggered = Column(Boolean, default=False, nullable=False)
    response_triggered = Column(Boolean, default=False, nullable=False)
    response_time_ms = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class CoverageGap(Base):
    __tablename__ = "coverage_gaps"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String, nullable=False, unique=True, index=True)
    severity = Column(String, default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    recommendation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
