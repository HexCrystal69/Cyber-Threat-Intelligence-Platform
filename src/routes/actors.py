from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from src.database import get_db
from src.models.actor import ThreatActor, ActorCampaign
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User

router = APIRouter(prefix="/actors", tags=["Threat Actors"])

allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])

@router.get("", response_model=List[dict])
def list_actors(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    actors = db.query(ThreatActor).all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "alias": a.alias,
            "country": a.country,
            "description": a.description,
            "confidence_score": a.confidence_score,
            "created_at": a.created_at
        } for a in actors
    ]

@router.get("/{actor_id}")
def get_actor(actor_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    actor = db.query(ThreatActor).filter(ThreatActor.id == actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
        
    actor_campaigns = db.query(ActorCampaign).filter(ActorCampaign.actor_id == actor_id).all()
    
    return {
        "id": actor.id,
        "name": actor.name,
        "alias": actor.alias,
        "country": actor.country,
        "description": actor.description,
        "confidence_score": actor.confidence_score,
        "created_at": actor.created_at,
        "campaigns": [
            {
                "campaign_id": ac.campaign_id,
                "attribution_reason": ac.attribution_reason,
                "confidence": ac.confidence,
                "evidence": ac.evidence_json
            } for ac in actor_campaigns
        ]
    }
