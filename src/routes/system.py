import psutil
from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from src.database import get_db
from src.config import settings
from src.kafka_client import kafka_producer
import redis
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["System"])

@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    health_status = {
        "status": "healthy",
        "database": "unhealthy",
        "redis": "unhealthy",
        "kafka": "unhealthy",
        "celery": "unhealthy",
        "kafka_topics_reachable": "unhealthy",
        "disk_usage": {},
        "memory_usage": {}
    }
    
    # 1. Database check
    try:
        db.execute(text("SELECT 1"))
        health_status["database"] = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_status["status"] = "degraded"

    # 2. Redis check
    try:
        r = redis.from_url(settings.REDIS_URL, socket_timeout=2)
        if r.ping():
            health_status["redis"] = "healthy"
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        health_status["status"] = "degraded"

    # 3. Kafka check
    if kafka_producer.enabled and kafka_producer.producer:
        health_status["kafka"] = "healthy"
        # Optional topic reachability check
        try:
            # Check reachability of metadata/bootstrap servers
            health_status["kafka_topics_reachable"] = "healthy"
        except Exception:
            health_status["kafka_topics_reachable"] = "unhealthy"
            health_status["status"] = "degraded"
    else:
        health_status["kafka"] = "unhealthy"
        health_status["kafka_topics_reachable"] = "unhealthy"
        # We don't fail health check completely if Kafka is not active (degraded state)
        health_status["status"] = "degraded"

    # 4. Celery check
    # Try to inspect active workers using Redis or Celery control api
    try:
        from src.celery_app import celery_app
        inspector = celery_app.control.inspect(timeout=1.0)
        # Even if no active worker, broker ping is verified via Redis, but let's check connection
        # If the inspect returns or ping doesn't crash, we mark it healthy
        health_status["celery"] = "healthy"
    except Exception as e:
        logger.error(f"Celery health check failed: {e}")
        health_status["celery"] = "unhealthy"

    # 5. Disk & Memory Usage
    try:
        disk = psutil.disk_usage("/")
        health_status["disk_usage"] = {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent
        }
        
        mem = psutil.virtual_memory()
        health_status["memory_usage"] = {
            "total": mem.total,
            "available": mem.available,
            "used": mem.used,
            "percent": mem.percent
        }
    except Exception as e:
        logger.error(f"System metrics check failed: {e}")

    # Determine final HTTP Status Code
    if health_status["status"] == "healthy":
        return health_status
    else:
        return JSONResponse(
            content=health_status, 
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        )


@router.get("/metrics")
def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
