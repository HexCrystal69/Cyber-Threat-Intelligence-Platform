# Deployment Guide

This guide details the procedure for deploying the platform to staging or production.

## Docker Compose Setup
The platform includes a [docker-compose.yml](file:///d:/Mini/Cyber-Threat-Intelligence-Platform/docker-compose.yml) file running the complete platform stack:
```bash
docker-compose up --build -d
```

This starts:
1. **Web Gateway**: FastAPI server on port `8000`.
2. **Workers**: Celery worker node.
3. **Database**: PostgreSQL.
4. **Queue**: Redis for Celery broker.
5. **Streaming**: Kafka & Zookeeper.
6. **Metrics**: Prometheus scraper.

## Frontend Hosting
Build production assets:
```bash
cd frontend
npm run build
```
Deploy the resulting `dist/` directory to static hosting services such as Vercel, Netlify, or AWS S3.
