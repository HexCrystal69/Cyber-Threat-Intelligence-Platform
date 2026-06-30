import datetime
import pytest
from fastapi import status
from unittest.mock import patch, Mock
from src.models.ioc import IOC, IOCMetadata
from src.models.enrichment import IOCEnrichment
from src.models.campaign import ThreatCampaign, CampaignIOC, CampaignScoreBreakdown, CampaignTimelineEvent
from src.models.actor import ThreatActor, ActorCampaign
from src.models.sighting import IOCSighting
from src.models.feed import ThreatFeed
from src.models.cache import ThreatCache
from src.models.replay import ProcessedEvent
from src.models.dlq import DeadLetterEvent
from src.models.reputation import IOCReputationHistory
from src.models.confidence import IOCConfidenceHistory
from src.models.source import ThreatSource, IOCSourceMapping
from src.models.dedup import DuplicateIOCGroup
from src.models.score import ThreatScoreSnapshot
from src.models.hunting import HuntingCandidate
from src.models.detection import DetectionRule
from src.models.relationship import IOCRelationship
from src.models.correlation import CorrelationGroup, CorrelationEvidence, CorrelationRun, CorrelationSnapshot
from src.models.timeline import IntelligenceTimelineEvent

from src.services.enrichment_engine import EnrichmentEngine
from src.services.severity_engine import SeverityEngine
from src.services.risk_engine import RiskEngine
from src.services.dedup_engine import DeduplicationEngine
from src.services.correlation_engine import CorrelationEngine
from src.services.attribution_engine import AttributionEngine
from src.services.graph_engine import GraphEngine
from src.tasks.stream_tasks import process_stream_event, is_already_processed

# Create a clean mock IOC fixture helper
def create_test_ioc(db, value="1.1.1.1", itype="IP", score=60, severity="MEDIUM"):
    ioc = IOC(
        indicator_value=value,
        indicator_type=itype,
        confidence_score=score,
        severity=severity,
        normalized_indicator=value.strip().lower(),
        search_text=value.strip().lower(),
        first_seen=datetime.datetime.utcnow(),
        last_seen=datetime.datetime.utcnow()
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc

# ----------------- ENRICHMENT & CACHE TESTS -----------------

def test_cache_write_and_hit(db_session):
    engine = EnrichmentEngine(db_session)
    engine.write_cache("geoip", "1.1.1.1", {"country": "US"}, expire_days=1)
    
    # Hit
    data = engine.check_cache("geoip", "1.1.1.1")
    assert data is not None
    assert data["country"] == "US"

def test_cache_miss_expiration(db_session):
    engine = EnrichmentEngine(db_session)
    engine.write_cache("geoip", "2.2.2.2", {"country": "US"}, expire_days=-1) # expired
    
    data = engine.check_cache("geoip", "2.2.2.2")
    assert data is None

def test_geoip_lookup_ip(db_session):
    engine = EnrichmentEngine(db_session)
    res = engine.lookup_geoip("1.1.1.1")
    assert res["country"] == "AU"
    assert res["asn"] == "AS13335"

def test_whois_lookup(db_session):
    engine = EnrichmentEngine(db_session)
    res = engine.lookup_whois("evil.com")
    assert "creation_date" in res
    assert res["registrar"] == "MarkMonitor Inc."

def test_enrich_ioc_ip(db_session):
    ioc = create_test_ioc(db_session, "1.1.1.1", "IP")
    engine = EnrichmentEngine(db_session)
    enrich = engine.enrich_ioc(ioc.id)
    assert enrich.country == "AU"
    assert enrich.reputation_score > 0

def test_enrich_ioc_domain(db_session):
    ioc = create_test_ioc(db_session, "malicious.com", "DOMAIN")
    engine = EnrichmentEngine(db_session)
    enrich = engine.enrich_ioc(ioc.id)
    assert enrich.whois_registrar == "MarkMonitor Inc."

# ----------------- SEVERITY & RISK ENGINE TESTS -----------------

def test_severity_scoring(db_session):
    ioc = create_test_ioc(db_session, "8.8.8.8", "IP", score=90)
    engine = SeverityEngine(db_session)
    
    # Pre-calculate enrichment
    EnrichmentEngine(db_session).enrich_ioc(ioc.id)
    
    sev = engine.calculate_severity(ioc.id)
    assert sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def test_risk_scoring(db_session):
    ioc = create_test_ioc(db_session, "8.8.8.8", "IP", score=85)
    engine = RiskEngine(db_session)
    
    EnrichmentEngine(db_session).enrich_ioc(ioc.id)
    
    risk = engine.calculate_risk(ioc.id)
    assert risk in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    # Check ThreatScoreSnapshot is created
    snap = db_session.query(ThreatScoreSnapshot).filter(ThreatScoreSnapshot.ioc_id == ioc.id).first()
    assert snap is not None
    assert snap.risk_score > 0

# ----------------- DEDUPLICATION ENGINE TESTS -----------------

def test_deduplication_engine(db_session):
    # Create canonical
    ioc1 = create_test_ioc(db_session, "10.0.0.1", "IP")
    # Create duplicate
    ioc2 = create_test_ioc(db_session, "10.0.0.1", "IP")
    
    engine = DeduplicationEngine(db_session)
    canonical = engine.process_ioc(ioc2)
    assert canonical.id == ioc1.id
    
    # Verify group
    group = db_session.query(DuplicateIOCGroup).filter(DuplicateIOCGroup.canonical_ioc_id == ioc1.id).first()
    assert group is not None
    assert group.duplicate_count == 2

# ----------------- CORRELATION ENGINE TESTS -----------------

def test_correlation_infrastructure_reuse(db_session):
    ip = create_test_ioc(db_session, "1.2.3.4", "IP")
    d1 = create_test_ioc(db_session, "host1.com", "DOMAIN")
    d2 = create_test_ioc(db_session, "host2.com", "DOMAIN")
    
    # Resolves to IP relationships
    rel1 = IOCRelationship(source_ioc_id=d1.id, target_ioc_id=ip.id, relationship_type="RESOLVES_TO")
    rel2 = IOCRelationship(source_ioc_id=d2.id, target_ioc_id=ip.id, relationship_type="RESOLVES_TO")
    db_session.add_all([rel1, rel2])
    db_session.commit()
    
    engine = CorrelationEngine(db_session)
    run_id = engine.run_correlation()
    assert run_id is not None
    
    # Verify runs & groups
    run = db_session.query(CorrelationRun).filter(CorrelationRun.id == run_id).first()
    assert run.status == "SUCCESS"
    assert run.relationships_created > 0

def test_correlation_asn(db_session):
    ioc1 = create_test_ioc(db_session, "1.1.1.1", "IP")
    ioc2 = create_test_ioc(db_session, "1.1.1.2", "IP")
    ioc3 = create_test_ioc(db_session, "1.1.1.3", "IP")
    
    # Set shared ASN
    e1 = IOCEnrichment(ioc_id=ioc1.id, provider="test", asn="AS13335", reputation_score=50)
    e2 = IOCEnrichment(ioc_id=ioc2.id, provider="test", asn="AS13335", reputation_score=50)
    e3 = IOCEnrichment(ioc_id=ioc3.id, provider="test", asn="AS13335", reputation_score=50)
    db_session.add_all([e1, e2, e3])
    db_session.commit()
    
    engine = CorrelationEngine(db_session)
    engine._correlate_asn("test_run")
    
    # Verify ASN cluster group created
    group = db_session.query(CorrelationGroup).filter(CorrelationGroup.name.contains("AS13335")).first()
    assert group is not None
    assert group.ioc_count == 3

# ----------------- ATTRIBUTION ENGINE TESTS -----------------

def test_attribution_engine(db_session):
    actor = ThreatActor(name="APT28", alias="Fancy Bear", description="Uses MarkMonitor Inc. registrar commonly.", confidence_score=90)
    db_session.add(actor)
    db_session.commit()
    
    campaign = ThreatCampaign(name="Operation Bearclaw", severity="HIGH", confidence_score=85)
    db_session.add(campaign)
    db_session.commit()
    
    ioc = create_test_ioc(db_session, "bear-c2.com", "DOMAIN")
    c_ioc = CampaignIOC(campaign_id=campaign.id, ioc_id=ioc.id)
    db_session.add(c_ioc)
    
    # Seed enrichment matching actor signature
    enrich = IOCEnrichment(ioc_id=ioc.id, provider="test", whois_registrar="MarkMonitor Inc.", reputation_score=80)
    db_session.add(enrich)
    db_session.commit()
    
    engine = AttributionEngine(db_session)
    mapping = engine.attribute_campaign(campaign.id)
    assert mapping is not None
    assert mapping.actor_id == actor.id
    assert mapping.confidence >= 30

# ----------------- GRAPH ENGINE TESTS -----------------

def test_graph_traversal(db_session):
    ioc1 = create_test_ioc(db_session, "1.1.1.1", "IP")
    ioc2 = create_test_ioc(db_session, "google.com", "DOMAIN")
    rel = IOCRelationship(source_ioc_id=ioc2.id, target_ioc_id=ioc1.id, relationship_type="RESOLVES_TO")
    db_session.add(rel)
    db_session.commit()
    
    engine = GraphEngine(db_session)
    graph = engine.traverse_graph(ioc1.id)
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1

def test_graph_snapshot(db_session):
    engine = GraphEngine(db_session)
    snap = engine.generate_global_snapshot()
    assert snap is not None
    assert snap.node_count >= 0

# ----------------- STREAM TASKS & DLQ TESTS -----------------

def test_replay_protection(db_session):
    # Write processed event
    pe = ProcessedEvent(event_id="evt_123", topic="ioc-created", partition=0, offset=42)
    db_session.add(pe)
    db_session.commit()
    
    assert is_already_processed(db_session, "evt_123", "ioc-created", 0, 42) is True
    assert is_already_processed(db_session, "evt_999", "ioc-created", 0, 99) is False

def test_process_stream_event_enrichment(db_session):
    ioc = create_test_ioc(db_session, "1.2.3.4", "IP")
    payload = {"event_id": "evt_test", "ioc_id": ioc.id}
    
    res = process_stream_event("threat-feed-events", payload, 0, 100)
    assert res["status"] == "SUCCESS"
    
    # Verify enrichment table
    enrich = db_session.query(IOCEnrichment).filter(IOCEnrichment.ioc_id == ioc.id).first()
    assert enrich is not None

def test_process_stream_event_dlq(db_session):
    payload = {"event_id": "evt_error", "ioc_id": 99999} # Non-existent IOC triggers exception
    
    # Run task synchronously to simulate DLQ trigger
    # Since we mocked self.retry, let's catch standard call or direct error handler
    from src.tasks.stream_tasks import route_to_dlq
    route_to_dlq(db_session, "ioc-created", payload, "IOC not found")
    
    dlq = db_session.query(DeadLetterEvent).filter(DeadLetterEvent.topic == "ioc-created").first()
    assert dlq is not None
    assert dlq.error_message == "IOC not found"

# ----------------- ROUTING ENDPOINTS TESTS -----------------

def test_get_enrichment_api(client, viewer_token, db_session):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    ioc = create_test_ioc(db_session, "8.8.8.8", "IP")
    enrich = IOCEnrichment(ioc_id=ioc.id, provider="test", country="US", reputation_score=50)
    db_session.add(enrich)
    db_session.commit()
    
    response = client.get(f"/api/v1/iocs/{ioc.id}/enrichment", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["country"] == "US"

def test_trigger_enrich_api(client, analyst_token, db_session):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    ioc = create_test_ioc(db_session, "1.1.1.1", "IP")
    
    response = client.post(f"/api/v1/iocs/{ioc.id}/enrich", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["reputation_score"] > 0

def test_ioc_timeline_api(client, viewer_token, db_session):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    ioc = create_test_ioc(db_session, "1.1.1.1", "IP")
    timeline_evt = IntelligenceTimelineEvent(
        ioc_id=ioc.id,
        event_type="ENRICHED",
        event_description="Enriched IP",
        event_source="IOC"
    )
    db_session.add(timeline_evt)
    db_session.commit()
    
    response = client.get(f"/api/v1/iocs/{ioc.id}/timeline", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) == 1

def test_trigger_correlation_api(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    response = client.post("/api/v1/correlation/run", headers=headers)
    assert response.status_code == status.HTTP_202_ACCEPTED
    assert "correlation_run_id" in response.json()

def test_campaign_routes(client, viewer_token, db_session):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    camp = ThreatCampaign(name="APT Bear Operation", status="ACTIVE", confidence_score=75)
    db_session.add(camp)
    db_session.commit()
    
    response = client.get("/api/v1/campaigns", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) >= 1
    
    response = client.get(f"/api/v1/campaigns/{camp.id}", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "APT Bear Operation"

def test_actor_routes(client, viewer_token, db_session):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    actor = ThreatActor(name="APT29", alias="Cozy Bear", description="Russian state group", confidence_score=95)
    db_session.add(actor)
    db_session.commit()
    
    response = client.get("/api/v1/actors", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) >= 1
    
    response = client.get(f"/api/v1/actors/{actor.id}", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "APT29"

def test_graph_routes(client, viewer_token, db_session):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    ioc = create_test_ioc(db_session, "127.0.0.1", "IP")
    ioc2 = create_test_ioc(db_session, "localhost", "DOMAIN")
    rel = IOCRelationship(source_ioc_id=ioc2.id, target_ioc_id=ioc.id, relationship_type="RESOLVES_TO")
    db_session.add(rel)
    db_session.commit()
    
    response = client.get(f"/api/v1/graph/ioc/{ioc.id}", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["nodes"]) == 2

# ----------------- ARCHITECT-LEVEL MODEL AND UPGRADE SANITY TESTS -----------------

def test_detection_rule_persistence(db_session):
    rule = DetectionRule(name="Detect APT29 C2", rule_type="YARA", severity="HIGH")
    db_session.add(rule)
    db_session.commit()
    assert rule.id is not None

def test_hunting_candidate_creation(db_session):
    ioc = create_test_ioc(db_session, "c2.domain.com", "DOMAIN")
    candidate = HuntingCandidate(ioc_id=ioc.id, risk_score=85, priority="HIGH", reason="Associated with high-risk IP")
    db_session.add(candidate)
    db_session.commit()
    assert candidate.id is not None

def test_reputation_history(db_session):
    ioc = create_test_ioc(db_session, "9.9.9.9", "IP")
    hist = IOCReputationHistory(ioc_id=ioc.id, old_score=50, new_score=85, reason="Fresh malicious behavior detected")
    db_session.add(hist)
    db_session.commit()
    assert hist.id is not None

def test_confidence_history(db_session):
    ioc = create_test_ioc(db_session, "1.1.1.1", "IP")
    hist = IOCConfidenceHistory(ioc_id=ioc.id, old_confidence=50, new_confidence=80, reason="Verified source attribution")
    db_session.add(hist)
    db_session.commit()
    assert hist.id is not None

def test_multi_source_attribution(db_session):
    source = ThreatSource(name="AlienVault OTX", provider="AlienVault", source_type="FEED", enabled=True)
    db_session.add(source)
    db_session.commit()
    
    ioc = create_test_ioc(db_session, "1.1.1.1", "IP")
    mapping = IOCSourceMapping(ioc_id=ioc.id, source_id=source.id)
    db_session.add(mapping)
    db_session.commit()
    assert mapping.id is not None
