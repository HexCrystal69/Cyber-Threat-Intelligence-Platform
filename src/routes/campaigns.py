from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from src.database import get_db
from src.models.campaign import ThreatCampaign, CampaignIOC, CampaignTimelineEvent
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User

router = APIRouter(prefix="/campaigns", tags=["Threat Campaigns"])

allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])

@router.get("", response_model=List[dict])
def list_campaigns(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    campaigns = db.query(ThreatCampaign).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "severity": c.severity,
            "status": c.status,
            "confidence_score": c.confidence_score,
            "first_seen": c.first_seen,
            "last_seen": c.last_seen,
            "created_at": c.created_at
        } for c in campaigns
    ]

@router.get("/{campaign_id}")
def get_campaign(campaign_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    campaign = db.query(ThreatCampaign).filter(ThreatCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
        
    c_iocs = db.query(CampaignIOC).filter(CampaignIOC.campaign_id == campaign_id).all()
    timeline = db.query(CampaignTimelineEvent).filter(CampaignTimelineEvent.campaign_id == campaign_id).all()
    
    return {
        "id": campaign.id,
        "name": campaign.name,
        "description": campaign.description,
        "severity": campaign.severity,
        "status": campaign.status,
        "confidence_score": campaign.confidence_score,
        "first_seen": campaign.first_seen,
        "last_seen": campaign.last_seen,
        "created_at": campaign.created_at,
        "ioc_ids": [ci.ioc_id for ci in c_iocs],
        "timeline": [
            {
                "event_type": t.event_type,
                "description": t.description,
                "created_at": t.created_at
            } for t in timeline
        ]
    }
