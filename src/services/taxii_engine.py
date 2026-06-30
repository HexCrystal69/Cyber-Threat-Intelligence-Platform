import datetime
from sqlalchemy.orm import Session
from src.models.taxii import TAXIICollection, TAXIISyncJob, TAXIICollectionState
from src.models.stix import STIXObject
from src.utils.metrics import taxii_sync_total

class TAXIIEngine:
    def __init__(self, db: Session):
        self.db = db

    def sync_collection(self, collection_id: str, sync_type: str = "pull", objects: list = None) -> dict:
        job = TAXIISyncJob(
            collection_id=collection_id,
            status="RUNNING",
            started_at=datetime.datetime.utcnow()
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)

        coll = self.db.query(TAXIICollection).filter(TAXIICollection.collection_id == collection_id).first()
        if not coll:
            job.status = "FAILED"
            job.completed_at = datetime.datetime.utcnow()
            self.db.commit()
            raise ValueError(f"Collection {collection_id} not found")

        coll.sync_status = "RUNNING"
        self.db.commit()

        try:
            synced_count = 0
            added = 0
            updated = 0

            if sync_type == "pull":
                # Simulated pull: fetching objects created/modified after last sync
                query = self.db.query(STIXObject)
                if coll.last_sync_at:
                    query = query.filter(STIXObject.created_at > coll.last_sync_at)
                pulled_objs = query.all()
                synced_count = len(pulled_objs)
                added = synced_count
                
                if pulled_objs:
                    coll.last_object_id = pulled_objs[-1].object_identifier

            elif sync_type == "push":
                if objects:
                    for obj in objects:
                        existing = self.db.query(STIXObject).filter(STIXObject.object_identifier == obj.get("id")).first()
                        if existing:
                            updated += 1
                        else:
                            added += 1
                        synced_count += 1
                    
                    coll.last_object_id = objects[-1].get("id")

            coll.last_sync_at = datetime.datetime.utcnow()
            coll.sync_status = "SUCCESS"
            
            state = TAXIICollectionState(
                collection_id=collection_id,
                objects_processed=synced_count,
                objects_added=added,
                objects_updated=updated,
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(state)

            job.status = "SUCCESS"
            job.objects_synced = synced_count
            job.completed_at = datetime.datetime.utcnow()
            self.db.commit()
            
            taxii_sync_total.labels(collection_id=collection_id, sync_type=sync_type).inc()
            return {"job_id": job.id, "status": "SUCCESS", "synced_count": synced_count}

        except Exception as e:
            coll.sync_status = "FAILED"
            job.status = "FAILED"
            job.completed_at = datetime.datetime.utcnow()
            self.db.commit()
            raise e
