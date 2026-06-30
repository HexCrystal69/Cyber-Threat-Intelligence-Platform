from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.knowledge_graph import GraphEntity, GraphRelationship
from src.services.knowledge_graph_engine import KnowledgeGraphEngine

router = APIRouter(prefix="/graph", tags=["Security Knowledge Graph"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])

@router.get("/entities", status_code=status.HTTP_200_OK)
def list_entities(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(GraphEntity).all()

@router.get("/relationships", status_code=status.HTTP_200_OK)
def list_relationships(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(GraphRelationship).all()

@router.get("/path", status_code=status.HTTP_200_OK)
def get_path(source_id: int, target_id: int, db: Session = Depends(get_db), current_user = Depends(allow_all)):
    engine = KnowledgeGraphEngine(db)
    try:
        return engine.discover_path(source_id, target_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
