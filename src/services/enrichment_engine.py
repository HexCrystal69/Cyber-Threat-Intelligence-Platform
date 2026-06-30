import datetime
import json
import logging
from sqlalchemy.orm import Session
from src.models.cache import ThreatCache
from src.models.ioc import IOC
from src.models.sighting import IOCSighting
from src.models.feed import ThreatFeed
from src.models.reputation import IOCReputationHistory
from src.models.enrichment import IOCEnrichment

logger = logging.getLogger(__name__)

class EnrichmentEngine:
    def __init__(self, db: Session):
        self.db = db

    def check_cache(self, provider: str, cache_key: str) -> dict | None:
        now = datetime.datetime.utcnow()
        cache_entry = self.db.query(ThreatCache).filter(
            ThreatCache.provider == provider,
            ThreatCache.cache_key == cache_key,
            ThreatCache.expires_at > now
        ).first()
        if cache_entry:
            return cache_entry.response_json
        return None

    def write_cache(self, provider: str, cache_key: str, data: dict, expire_days: int = 1):
        # Delete old cache entry if exists
        old = self.db.query(ThreatCache).filter(
            ThreatCache.provider == provider,
            ThreatCache.cache_key == cache_key
        ).first()
        if old:
            self.db.delete(old)
            self.db.commit()

        expires = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
        cache_entry = ThreatCache(
            provider=provider,
            cache_key=cache_key,
            response_json=data,
            expires_at=expires
        )
        self.db.add(cache_entry)
        self.db.commit()

    def lookup_geoip(self, ip_value: str) -> dict:
        cache_data = self.check_cache("geoip", ip_value)
        if cache_data:
            return cache_data

        # Mock GeoIP resolver
        # Real implementations would query services like maxmind or ip-api
        data = {
            "country": "US",
            "asn": "AS15169",
            "organization": "Google LLC",
            "isp": "Google LLC"
        }
        if ip_value.startswith("1.1.1."):
            data = {
                "country": "AU",
                "asn": "AS13335",
                "organization": "Cloudflare Inc",
                "isp": "Cloudflare Inc"
            }
        
        self.write_cache("geoip", ip_value, data, expire_days=7)
        return data

    def lookup_whois(self, domain_value: str) -> dict:
        cache_data = self.check_cache("whois", domain_value)
        if cache_data:
            return cache_data

        # Mock WHOIS resolver
        now_str = datetime.datetime.utcnow().isoformat()
        created_str = (datetime.datetime.utcnow() - datetime.timedelta(days=365)).isoformat()
        expires_str = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
        
        data = {
            "registrar": "MarkMonitor Inc.",
            "creation_date": created_str,
            "expiration_date": expires_str
        }
        
        self.write_cache("whois", domain_value, data, expire_days=30)
        return data

    def calculate_reputation(self, ioc: IOC) -> int:
        # Reputation Score Formula:
        # 40% Feed Reputation
        # 30% Frequency (Sightings count)
        # 20% Age (Newer indicators have higher freshness threat)
        # 10% Confidence

        # 1. Feed trust score (0-100)
        feed_reputation = 50
        if ioc.source_feed_id:
            feed = self.db.query(ThreatFeed).filter(ThreatFeed.id == ioc.source_feed_id).first()
            if feed:
                feed_reputation = int(feed.trust_score * 100)

        # 2. Sightings frequency
        sightings = self.db.query(IOCSighting).filter(IOCSighting.ioc_id == ioc.id).all()
        sighting_count = sum(s.sighting_count for s in sightings)
        frequency = min(sighting_count * 10, 100)

        # 3. Freshness / Age (0-100, where fresh = 100, old = 0)
        now = datetime.datetime.utcnow()
        days_since_first = (now - ioc.first_seen).days
        age_score = max(100 - (days_since_first * 2), 0)

        # 4. Confidence
        confidence = ioc.confidence_score

        # Calculate weighted average
        rep_score = int(
            (0.40 * feed_reputation) +
            (0.30 * frequency) +
            (0.20 * age_score) +
            (0.10 * confidence)
        )
        return max(0, min(rep_score, 100))

    def enrich_ioc(self, ioc_id: int) -> IOCEnrichment:
        ioc = self.db.query(IOC).filter(IOC.id == ioc_id).first()
        if not ioc:
            raise ValueError(f"IOC ID {ioc_id} not found")

        country = None
        asn = None
        org = None
        whois_registrar = None
        whois_created = None
        raw_info = {}

        # Query based on indicator type
        if ioc.indicator_type.upper() == "IP":
            geoip_data = self.lookup_geoip(ioc.indicator_value)
            country = geoip_data.get("country")
            asn = geoip_data.get("asn")
            org = geoip_data.get("organization")
            raw_info["geoip"] = geoip_data
        elif ioc.indicator_type.upper() in ["DOMAIN", "URL"]:
            domain = ioc.indicator_value
            if ioc.indicator_type.upper() == "URL":
                from urllib.parse import urlparse
                try:
                    domain = urlparse(ioc.indicator_value).netloc or ioc.indicator_value
                except Exception:
                    pass
            
            whois_data = self.lookup_whois(domain)
            whois_registrar = whois_data.get("registrar")
            if whois_data.get("creation_date"):
                whois_created = datetime.datetime.fromisoformat(whois_data.get("creation_date"))
            raw_info["whois"] = whois_data

        new_reputation = self.calculate_reputation(ioc)

        # Save reputation history if changed or brand new
        existing_enrichment = self.db.query(IOCEnrichment).filter(IOCEnrichment.ioc_id == ioc.id).first()
        old_score = 0
        if existing_enrichment:
            old_score = existing_enrichment.reputation_score
            
        if not existing_enrichment or old_score != new_reputation:
            rep_history = IOCReputationHistory(
                ioc_id=ioc.id,
                old_score=old_score,
                new_score=new_reputation,
                reason="Enrichment calculation update"
            )
            self.db.add(rep_history)

        if existing_enrichment:
            # Update
            existing_enrichment.country = country
            existing_enrichment.asn = asn
            existing_enrichment.organization = org
            existing_enrichment.whois_registrar = whois_registrar
            existing_enrichment.whois_created_date = whois_created
            existing_enrichment.reputation_score = new_reputation
            existing_enrichment.confidence_score = ioc.confidence_score
            existing_enrichment.raw_response_json = raw_info
            self.db.commit()
            self.db.refresh(existing_enrichment)
            return existing_enrichment
        else:
            # Create
            enrichment = IOCEnrichment(
                ioc_id=ioc.id,
                provider="CTIPEngine",
                country=country,
                asn=asn,
                organization=org,
                whois_registrar=whois_registrar,
                whois_created_date=whois_created,
                reputation_score=new_reputation,
                confidence_score=ioc.confidence_score,
                raw_response_json=raw_info
            )
            self.db.add(enrichment)
            self.db.commit()
            self.db.refresh(enrichment)
            return enrichment
