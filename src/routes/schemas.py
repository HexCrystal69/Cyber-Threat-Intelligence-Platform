from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.schema_registry import EventSchema, SchemaValidationRun
from src.services.schema_registry_engine import SchemaRegistryEngine
from typing import List, Dict, Any

router = APIRouter(prefix="/schemas", tags=["Security Event Schema Registry"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("", status_code=status.HTTP_200_OK)
def list_schemas(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(EventSchema).all()

@router.post("", status_code=status.HTTP_201_CREATED)
def create_schema(name: str, version: str, schema_json: str, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = SchemaRegistryEngine(db)
    return engine.register_schema(name, version, schema_json)

@router.post("/validate", status_code=status.HTTP_200_OK)
def validate_events_with_schema(schema_id: int, events: List[Dict[str, Any]], db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = SchemaRegistryEngine(db)
    try:
        return engine.validate_events(schema_id, events)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/validation", status_code=status.HTTP_200_OK)
def list_validation_runs(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(SchemaValidationRun).all()
