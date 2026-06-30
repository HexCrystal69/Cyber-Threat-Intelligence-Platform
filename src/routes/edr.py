from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.edr import EndpointAsset, EndpointDetection

router = APIRouter(tags=["EDR Management"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])

@router.get("/endpoints", status_code=status.HTTP_200_OK)
def list_endpoints(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(EndpointAsset).all()

@router.get("/endpoints/{id}", status_code=status.HTTP_200_OK)
def get_endpoint(id: int, db: Session = Depends(get_db), current_user = Depends(allow_all)):
    asset = db.query(EndpointAsset).filter(EndpointAsset.id == id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Endpoint asset not found")
    return asset

@router.get("/detections", status_code=status.HTTP_200_OK)
def list_detections(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(EndpointDetection).all()
