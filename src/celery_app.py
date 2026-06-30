import os
from celery import Celery
from src.config import settings

celery_app = Celery(
    "ctip_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "src.tasks.ingestion_tasks",
        "src.tasks.alert_tasks",
        "src.tasks.case_tasks",
        "src.tasks.detection_tasks",
        "src.tasks.stream_tasks",
        "src.tasks.sharing_tasks",
        "src.tasks.response_tasks",
        "src.tasks.siem_tasks",
        "src.tasks.edr_tasks",
        "src.tasks.purple_team_tasks",
        "src.tasks.copilot_tasks",
        "src.tasks.rag_tasks",
        "src.tasks.graph_tasks"
    ]
)

celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)
