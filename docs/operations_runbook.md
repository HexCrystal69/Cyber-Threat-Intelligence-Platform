# Operations Runbook

This runbook outlines day-to-day operations and procedures for system administrators.

## Monitoring Metrics
Scrape metrics on `/metrics` endpoint. 
Prometheus config scraper is located in [prometheus.yml](file:///d:/Mini/Cyber-Threat-Intelligence-Platform/prometheus.yml).

### Critical Indicators
- `copilot_requests_total`: Monitor AI query volumes.
- `ai_validation_runs_total`: Tracks responses analyzed for validation audits.
- `documents_embedded_total`: Monitors RAG document indexing rate.

## Troubleshooting Tasks
1. **Restarting Celery Worker**:
   ```bash
   docker-compose restart celery_worker
   ```
2. **Purging Task Queue**:
   If tasks are backing up:
   ```bash
   celery -A src.celery_app purge
   ```
