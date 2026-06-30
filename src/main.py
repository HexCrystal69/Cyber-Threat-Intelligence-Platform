import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from src.config import settings
from src.database import engine, Base, SessionLocal
from src.kafka_client import kafka_producer
from src.models.feed import ThreatFeed
from src.routes import auth, feeds, iocs, jobs, system, correlation, campaigns, actors, graph, detections, alerts, cases, hunting, playbooks, dashboard, stix, taxii, misp, response, sharing, siem, edr, datalake, purple_team, compliance, detection_analytics, coverage, soc, rules, schemas, exposure, copilot, rag, detection_ai, ai_governance, ai_usage, query_translation, graph_analytics

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Seed initial threat feeds if they do not exist
def seed_default_feeds():
    db = SessionLocal()
    try:
        default_feeds = [
            {
                "name": "OpenPhish",
                "source_url": "https://openphish.com/feed.txt",
                "provider": "OpenPhish",
                "feed_type": "TXT",
                "enabled": True
            },
            {
                "name": "AbuseIPDB",
                "source_url": "https://api.abuseipdb.com/api/v2/blacklist",
                "provider": "AbuseIPDB",
                "feed_type": "JSON",
                "enabled": True
            }
        ]
        for feed_data in default_feeds:
            existing = db.query(ThreatFeed).filter(ThreatFeed.name == feed_data["name"]).first()
            if not existing:
                feed = ThreatFeed(**feed_data)
                db.add(feed)
                db.commit()
                logger.info(f"Seeded default threat feed: {feed_data['name']}")
    except Exception as e:
        logger.error(f"Error seeding default feeds: {e}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create database tables, connect Kafka, seed feeds
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logger.error(f"Database table creation failed: {e}")

    await kafka_producer.start()
    seed_default_feeds()
    
    yield
    
    # Shutdown: Clean up Kafka producer
    await kafka_producer.stop()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Cyber Threat Intelligence Platform - Ingestion & Normalization Service",
    version="1.0.0",
    lifespan=lifespan
)

# Register routes
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(feeds.router, prefix=settings.API_V1_STR)
app.include_router(iocs.router, prefix=settings.API_V1_STR)
app.include_router(jobs.router, prefix=settings.API_V1_STR)
app.include_router(correlation.router, prefix=settings.API_V1_STR)
app.include_router(campaigns.router, prefix=settings.API_V1_STR)
app.include_router(actors.router, prefix=settings.API_V1_STR)
app.include_router(graph.router, prefix=settings.API_V1_STR)
app.include_router(detections.router, prefix=settings.API_V1_STR)
app.include_router(alerts.router, prefix=settings.API_V1_STR)
app.include_router(cases.router, prefix=settings.API_V1_STR)
app.include_router(hunting.router, prefix=settings.API_V1_STR)
app.include_router(playbooks.router, prefix=settings.API_V1_STR)
app.include_router(dashboard.router, prefix=settings.API_V1_STR)
app.include_router(stix.router, prefix=settings.API_V1_STR)
app.include_router(taxii.router, prefix=settings.API_V1_STR)
app.include_router(misp.router, prefix=settings.API_V1_STR)
app.include_router(response.router, prefix=settings.API_V1_STR)
app.include_router(sharing.router, prefix=settings.API_V1_STR)
app.include_router(siem.router, prefix=settings.API_V1_STR)
app.include_router(edr.router, prefix=settings.API_V1_STR)
app.include_router(datalake.router, prefix=settings.API_V1_STR)
app.include_router(purple_team.router, prefix=settings.API_V1_STR)
app.include_router(compliance.router, prefix=settings.API_V1_STR)
app.include_router(detection_analytics.router, prefix=settings.API_V1_STR)
app.include_router(coverage.router, prefix=settings.API_V1_STR)
app.include_router(soc.router, prefix=settings.API_V1_STR)
app.include_router(rules.router, prefix=settings.API_V1_STR)
app.include_router(schemas.router, prefix=settings.API_V1_STR)
app.include_router(exposure.router, prefix=settings.API_V1_STR)
app.include_router(copilot.router, prefix=settings.API_V1_STR)
app.include_router(rag.router, prefix=settings.API_V1_STR)
app.include_router(detection_ai.router, prefix=settings.API_V1_STR)
app.include_router(ai_governance.router, prefix=settings.API_V1_STR)
app.include_router(ai_usage.router, prefix=settings.API_V1_STR)
app.include_router(query_translation.router, prefix=settings.API_V1_STR)
app.include_router(graph_analytics.router, prefix=settings.API_V1_STR)
app.include_router(system.router)
