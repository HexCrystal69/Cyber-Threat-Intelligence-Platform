import datetime
import uuid
import logging
from sqlalchemy.orm import Session
from src.models.ioc import IOC, IOCMetadata
from src.models.enrichment import IOCEnrichment
from src.models.relationship import IOCRelationship
from src.models.correlation import CorrelationGroup, CorrelationEvidence, CorrelationRun, CorrelationSnapshot
from src.utils.text import levenshtein_distance

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self, db: Session):
        self.db = db

    def run_correlation(self) -> str:
        run_id = f"corr_run_{uuid.uuid4()}"
        run_entry = CorrelationRun(
            id=run_id,
            status="RUNNING",
            started_at=datetime.datetime.utcnow()
        )
        self.db.add(run_entry)
        self.db.commit()

        try:
            total_iocs = self.db.query(IOC).count()
            run_entry.total_iocs = total_iocs
            self.db.commit()

            groups_created = 0
            relationships_created = 0

            # 1. Infrastructure Reuse
            relationships_created += self._correlate_infrastructure_reuse(run_id)

            # 2. ASN Correlation
            groups_created += self._correlate_asn(run_id)

            # 3. Domain Similarity
            relationships_created += self._correlate_domain_similarity(run_id)

            # 4. Campaign Clustering (Clustering based on shared properties)
            groups_created += self._correlate_campaign_clustering(run_id)

            # Generate Snapshot
            snapshot_json = {
                "run_id": run_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "iocs_processed": total_iocs,
                "groups": groups_created,
                "relationships": relationships_created
            }
            snapshot = CorrelationSnapshot(
                correlation_run_id=run_id,
                group_count=groups_created,
                relationship_count=relationships_created,
                snapshot_json=snapshot_json
            )
            self.db.add(snapshot)

            run_entry.status = "SUCCESS"
            run_entry.groups_created = groups_created
            run_entry.relationships_created = relationships_created
            run_entry.completed_at = datetime.datetime.utcnow()
            self.db.commit()
            
            return run_id
        except Exception as e:
            logger.error(f"Correlation run {run_id} failed: {e}")
            self.db.rollback()
            run_entry.status = "FAILED"
            run_entry.error_message = str(e)
            run_entry.completed_at = datetime.datetime.utcnow()
            self.db.commit()
            raise

    def _correlate_infrastructure_reuse(self, run_id: str) -> int:
        # Find RESOLVES_TO relationships and group domains resolving to the same IP
        resolves = self.db.query(IOCRelationship).filter(
            IOCRelationship.relationship_type == "RESOLVES_TO"
        ).all()

        ip_to_domains = {}
        for r in resolves:
            ip_to_domains.setdefault(r.target_ioc_id, []).append(r.source_ioc_id)

        relationships_created = 0
        for ip_id, domain_ids in ip_to_domains.items():
            if len(domain_ids) > 1:
                # Create Correlation Group
                group = CorrelationGroup(
                    name=f"Infrastructure Reuse - IP: {ip_id}",
                    severity="HIGH",
                    confidence_score=75,
                    ioc_count=len(domain_ids) + 1
                )
                self.db.add(group)
                self.db.commit()
                self.db.refresh(group)

                # Add Evidence for IP
                evidence_ip = CorrelationEvidence(
                    correlation_group_id=group.id,
                    ioc_id=ip_id,
                    evidence_type="IP_REUSE",
                    evidence_value=f"IP resolves to {len(domain_ids)} domains",
                    confidence=75,
                    weight=0.4,
                    score_contribution=30.0
                )
                self.db.add(evidence_ip)

                for d_id in domain_ids:
                    evidence_d = CorrelationEvidence(
                        correlation_group_id=group.id,
                        ioc_id=d_id,
                        evidence_type="DOMAIN_REUSE",
                        evidence_value=f"Domain resolves to shared IP {ip_id}",
                        confidence=75,
                        weight=0.4,
                        score_contribution=30.0
                    )
                    self.db.add(evidence_d)

                    # Create SHARES_INFRASTRUCTURE relationships between domains
                    for other_d_id in domain_ids:
                        if d_id != other_d_id:
                            existing = self.db.query(IOCRelationship).filter(
                                IOCRelationship.source_ioc_id == d_id,
                                IOCRelationship.target_ioc_id == other_d_id,
                                IOCRelationship.relationship_type == "SHARES_INFRASTRUCTURE"
                            ).first()
                            if not existing:
                                rel = IOCRelationship(
                                    source_ioc_id=d_id,
                                    target_ioc_id=other_d_id,
                                    relationship_type="SHARES_INFRASTRUCTURE",
                                    confidence_score=70,
                                    relationship_strength="STRONG",
                                    evidence_json={"shared_ip": ip_id}
                                )
                                self.db.add(rel)
                                relationships_created += 1

                self.db.commit()
        return relationships_created

    def _correlate_asn(self, run_id: str) -> int:
        enrichments = self.db.query(IOCEnrichment).filter(
            IOCEnrichment.asn != None
        ).all()

        asn_groups = {}
        for e in enrichments:
            asn_groups.setdefault(e.asn, []).append(e.ioc_id)

        groups_created = 0
        for asn, ioc_ids in asn_groups.items():
            if len(ioc_ids) > 2:  # Correlate if 3 or more IOCs share same ASN
                group = CorrelationGroup(
                    name=f"ASN Cluster - {asn}",
                    severity="MEDIUM",
                    confidence_score=60,
                    ioc_count=len(ioc_ids)
                )
                self.db.add(group)
                self.db.commit()
                self.db.refresh(group)
                groups_created += 1

                for ioc_id in ioc_ids:
                    ev = CorrelationEvidence(
                        correlation_group_id=group.id,
                        ioc_id=ioc_id,
                        evidence_type="ASN_MATCH",
                        evidence_value=f"IOC located in ASN {asn}",
                        confidence=60,
                        weight=0.3,
                        score_contribution=18.0
                    )
                    self.db.add(ev)
                self.db.commit()
        return groups_created

    def _correlate_domain_similarity(self, run_id: str) -> int:
        domains = self.db.query(IOC).filter(IOC.indicator_type == "DOMAIN").all()
        relationships_created = 0

        for i in range(len(domains)):
            for j in range(i + 1, len(domains)):
                d1 = domains[i]
                d2 = domains[j]
                
                # Compare similarity if length is reasonable
                if len(d1.indicator_value) >= 6 and len(d2.indicator_value) >= 6:
                    dist = levenshtein_distance(d1.indicator_value, d2.indicator_value)
                    if dist <= 2:
                        # Create domain similarity relationship
                        existing = self.db.query(IOCRelationship).filter(
                            IOCRelationship.source_ioc_id == d1.id,
                            IOCRelationship.target_ioc_id == d2.id,
                            IOCRelationship.relationship_type == "ASSOCIATED_WITH"
                        ).first()
                        
                        if not existing:
                            rel = IOCRelationship(
                                source_ioc_id=d1.id,
                                target_ioc_id=d2.id,
                                relationship_type="ASSOCIATED_WITH",
                                confidence_score=65,
                                relationship_strength="MEDIUM",
                                evidence_json={"levenshtein_distance": dist}
                            )
                            self.db.add(rel)
                            relationships_created += 1
        self.db.commit()
        return relationships_created

    def _correlate_campaign_clustering(self, run_id: str) -> int:
        # Group based on shared tags in metadata
        metadata = self.db.query(IOCMetadata).all()
        tag_to_iocs = {}
        for m in metadata:
            if m.tags:
                for tag in m.tags:
                    tag_to_iocs.setdefault(tag, []).append(m.ioc_id)

        groups_created = 0
        for tag, ioc_ids in tag_to_iocs.items():
            if len(ioc_ids) >= 3:
                group = CorrelationGroup(
                    name=f"Campaign Cluster - Tag: {tag}",
                    severity="HIGH",
                    confidence_score=80,
                    ioc_count=len(ioc_ids)
                )
                self.db.add(group)
                self.db.commit()
                self.db.refresh(group)
                groups_created += 1

                for ioc_id in ioc_ids:
                    ev = CorrelationEvidence(
                        correlation_group_id=group.id,
                        ioc_id=ioc_id,
                        evidence_type="TAG_MATCH",
                        evidence_value=f"IOC shares campaign tag {tag}",
                        confidence=80,
                        weight=0.3,
                        score_contribution=24.0
                    )
                    self.db.add(ev)
                self.db.commit()
        return groups_created
