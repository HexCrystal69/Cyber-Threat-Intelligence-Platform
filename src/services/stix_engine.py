import json
import uuid
import datetime
from sqlalchemy.orm import Session
from src.models.stix import STIXBundle, STIXObject, STIXRelationship
from src.utils.metrics import stix_bundles_generated_total

class STIXEngine:
    def __init__(self, db: Session):
        self.db = db

    def generate_bundle(self, objects: list) -> dict:
        bundle_id = f"bundle--{uuid.uuid4()}"
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects
        }
        
        db_bundle = STIXBundle(
            bundle_id=bundle_id,
            object_count=len(objects),
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(db_bundle)
        
        for obj in objects:
            # Check unique identifier to avoid duplicate object errors
            existing = self.db.query(STIXObject).filter(STIXObject.object_identifier == obj.get("id")).first()
            if existing:
                continue
            db_obj = STIXObject(
                bundle_id=bundle_id,
                object_type=obj.get("type"),
                object_identifier=obj.get("id"),
                object_json=json.dumps(obj),
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(db_obj)
            
            if obj.get("type") == "relationship":
                rel = STIXRelationship(
                    source_object_id=obj.get("source_ref"),
                    target_object_id=obj.get("target_ref"),
                    relationship_type=obj.get("relationship_type"),
                    description=obj.get("description"),
                    created_at=datetime.datetime.utcnow()
                )
                self.db.add(rel)
                
        self.db.commit()
        stix_bundles_generated_total.inc()
        return bundle

    def validate_object(self, obj: dict) -> bool:
        required_fields = ["type", "id", "spec_version"]
        if not all(field in obj for field in required_fields):
            return False
        if obj.get("spec_version") != "2.1":
            return False
        if not obj.get("id").startswith(f"{obj.get('type')}--"):
            return False
        return True

    def parse_bundle(self, bundle_json: str) -> list:
        try:
            bundle = json.loads(bundle_json)
        except Exception:
            raise ValueError("Invalid JSON format")
            
        if bundle.get("type") != "bundle" or bundle.get("spec_version") != "2.1":
            raise ValueError("Not a valid STIX 2.1 bundle")
            
        valid_objects = []
        for obj in bundle.get("objects", []):
            if self.validate_object(obj):
                valid_objects.append(obj)
                
        return valid_objects
