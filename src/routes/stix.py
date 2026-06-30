from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.stix import STIXBundle, STIXObject
from src.services.stix_engine import STIXEngine

router = APIRouter(prefix="/stix", tags=["STIX Management"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.post("/export", status_code=status.HTTP_200_OK)
def export_stix_bundle(objects: List[Dict[str, Any]], db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = STIXEngine(db)
    return engine.generate_bundle(objects)

@router.post("/import", status_code=status.HTTP_200_OK)
def import_stix_bundle(bundle: Dict[str, Any], db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = STIXEngine(db)
    try:
        import json
        objs = engine.parse_bundle(json.dumps(bundle))
        imported_objs = []
        for obj in objs:
            existing = db.query(STIXObject).filter(STIXObject.object_identifier == obj.get("id")).first()
            if existing:
                continue
            db_obj = STIXObject(
                object_type=obj.get("type"),
                object_identifier=obj.get("id"),
                object_json=json.dumps(obj)
            )
            db.add(db_obj)
            imported_objs.append(obj)
        db.commit()
        return {"status": "SUCCESS", "imported_count": len(imported_objs)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/bundles", status_code=status.HTTP_200_OK)
def list_stix_bundles(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(STIXBundle).all()
