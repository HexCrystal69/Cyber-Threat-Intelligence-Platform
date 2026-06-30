import datetime
from sqlalchemy.orm import Session
from src.models.misp import MISPInstance, MISPSyncJob, MISPEvent, MISPAttribute
from src.models.ioc import IOC
from src.models.campaign import ThreatCampaign
from src.utils.metrics import misp_sync_total

class MISPEngine:
    def __init__(self, db: Session):
        self.db = db

    def sync_instance(self, instance_id: int, direction: str = "both") -> dict:
        instance = self.db.query(MISPInstance).filter(MISPInstance.id == instance_id).first()
        if not instance or not instance.enabled:
            raise ValueError("MISP Instance not found or disabled")

        job = MISPSyncJob(
            instance_id=instance_id,
            status="RUNNING",
            started_at=datetime.datetime.utcnow()
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)

        try:
            imported = 0
            exported = 0

            if direction in ("import", "both"):
                misp_attrs = self.db.query(MISPAttribute).all()
                for attr in misp_attrs:
                    existing_ioc = self.db.query(IOC).filter(IOC.indicator_value == attr.value).first()
                    if not existing_ioc:
                        new_ioc = IOC(
                            indicator_value=attr.value,
                            indicator_type=attr.attribute_type,
                            confidence_score=75,
                            severity="HIGH",
                            normalized_indicator=attr.value.lower(),
                            search_text=attr.value.lower(),
                            first_seen=datetime.datetime.utcnow(),
                            last_seen=datetime.datetime.utcnow()
                        )
                        self.db.add(new_ioc)
                        imported += 1
                self.db.commit()

            if direction in ("export", "both"):
                iocs = self.db.query(IOC).all()
                event = MISPEvent(
                    misp_event_id=f"misp-event-{datetime.datetime.utcnow().timestamp()}",
                    title="Exported Indicators from CTIP",
                    threat_level="High",
                    published=True,
                    created_at=datetime.datetime.utcnow()
                )
                self.db.add(event)
                self.db.commit()
                self.db.refresh(event)

                for ioc in iocs:
                    existing_attr = self.db.query(MISPAttribute).filter(
                        MISPAttribute.event_id == event.id,
                        MISPAttribute.value == ioc.indicator_value
                    ).first()
                    if not existing_attr:
                        attr = MISPAttribute(
                            event_id=event.id,
                            attribute_type=ioc.indicator_type,
                            value=ioc.indicator_value,
                            category="Network activity",
                            created_at=datetime.datetime.utcnow()
                        )
                        self.db.add(attr)
                        exported += 1
                self.db.commit()

            job.status = "SUCCESS"
            job.imported_iocs = imported
            job.exported_iocs = exported
            job.completed_at = datetime.datetime.utcnow()
            self.db.commit()

            misp_sync_total.labels(instance_name=instance.name).inc()
            return {"job_id": job.id, "status": "SUCCESS", "imported": imported, "exported": exported}

        except Exception as e:
            job.status = "FAILED"
            job.completed_at = datetime.datetime.utcnow()
            self.db.commit()
            raise e

    def export_campaign(self, campaign_id: int) -> dict:
        campaign = self.db.query(ThreatCampaign).filter(ThreatCampaign.id == campaign_id).first()
        if not campaign:
            raise ValueError("Campaign not found")
        
        event = MISPEvent(
            misp_event_id=f"campaign-{campaign.id}",
            title=f"Campaign: {campaign.name}",
            threat_level="High",
            published=True,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return {"misp_event_id": event.misp_event_id, "title": event.title}

    def import_campaign(self, misp_event_id: str) -> dict:
        event = self.db.query(MISPEvent).filter(MISPEvent.misp_event_id == misp_event_id).first()
        if not event:
            raise ValueError("MISP event not found")
        
        existing_campaign = self.db.query(ThreatCampaign).filter(ThreatCampaign.name == event.title).first()
        if not existing_campaign:
            new_camp = ThreatCampaign(
                name=event.title,
                description=f"Imported from MISP event {misp_event_id}",
                first_seen=datetime.datetime.utcnow()
            )
            self.db.add(new_camp)
            self.db.commit()
            self.db.refresh(new_camp)
            return {"campaign_id": new_camp.id, "name": new_camp.name}
        return {"campaign_id": existing_campaign.id, "name": existing_campaign.name}
