import datetime
from sqlalchemy.orm import Session
from src.models.edr import EDRConnector, EndpointAsset, EndpointDetection
from src.models.ioc import IOC
from src.models.case import CaseEvidence
from src.utils.metrics import edr_assets_total, edr_detections_total

class EDREngine:
    def __init__(self, db: Session):
        self.db = db

    def sync_endpoint(self, asset_data: dict) -> EndpointAsset:
        asset = self.db.query(EndpointAsset).filter(EndpointAsset.hostname == asset_data["hostname"]).first()
        if not asset:
            asset = EndpointAsset(
                hostname=asset_data["hostname"],
                operating_system=asset_data.get("operating_system"),
                ip_address=asset_data.get("ip_address"),
                asset_criticality=asset_data.get("asset_criticality", "MEDIUM"),
                business_owner=asset_data.get("business_owner"),
                department=asset_data.get("department"),
                last_seen=datetime.datetime.utcnow()
            )
            self.db.add(asset)
            self.db.commit()
            self.db.refresh(asset)
            edr_assets_total.inc()
        else:
            asset.operating_system = asset_data.get("operating_system", asset.operating_system)
            asset.ip_address = asset_data.get("ip_address", asset.ip_address)
            asset.asset_criticality = asset_data.get("asset_criticality", asset.asset_criticality)
            asset.business_owner = asset_data.get("business_owner", asset.business_owner)
            asset.department = asset_data.get("department", asset.department)
            asset.last_seen = datetime.datetime.utcnow()
            self.db.commit()

        return asset

    def calculate_risk(self, endpoint_id: int) -> float:
        asset = self.db.query(EndpointAsset).filter(EndpointAsset.id == endpoint_id).first()
        if not asset:
            raise ValueError("Endpoint not found")

        active_dets = self.db.query(EndpointDetection).filter(
            EndpointDetection.endpoint_id == endpoint_id,
            EndpointDetection.status == "OPEN"
        ).all()
        active_count = len(active_dets)

        severity_map = {"LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 100}
        max_severity = 0
        for det in active_dets:
            val = severity_map.get(det.severity.upper(), 0)
            if val > max_severity:
                max_severity = val

        ioc_count = self.db.query(IOC).filter(IOC.indicator_value == asset.ip_address).count()
        ioc_score = min(100, ioc_count * 20)

        incident_count = self.db.query(CaseEvidence).filter(
            CaseEvidence.evidence_type == "ENDPOINT",
            CaseEvidence.evidence_metadata.contains(asset.hostname)
        ).count()
        incident_score = min(100, incident_count * 25)

        crit_map = {"LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 100}
        crit_score = crit_map.get(asset.asset_criticality.upper(), 50)

        active_score = min(100, active_count * 20)
        risk = (0.30 * active_score +
                0.20 * max_severity +
                0.15 * ioc_score +
                0.15 * incident_score +
                0.20 * crit_score)

        asset.risk_score = risk
        self.db.commit()
        return risk
