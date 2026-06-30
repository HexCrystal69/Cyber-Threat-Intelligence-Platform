from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.knowledge_graph import GraphCommunity
from src.services.graph_analytics_engine import GraphAnalyticsEngine

router = APIRouter(prefix="/graph", tags=["Security Knowledge Graph Analytics"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("/communities", status_code=status.HTTP_200_OK)
def get_graph_communities(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    latest = db.query(GraphCommunity).all()
    if not latest:
        # Detect dynamically
        engine = GraphAnalyticsEngine(db)
        return engine.detect_communities()
    return latest

@router.get("/high-risk-clusters", status_code=status.HTTP_200_OK)
def get_high_risk_clusters(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    engine = GraphAnalyticsEngine(db)
    return engine.discover_high_risk_clusters()
