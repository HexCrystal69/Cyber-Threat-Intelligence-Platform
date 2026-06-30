# Cyber Threat Intelligence Platform

## Overview
An enterprise-grade Cyber Threat Intelligence, Detection Engineering, SIEM, EDR, SOAR, AI Security Copilot, Threat Hunting, and Security Analytics platform.

---

## Features

### Threat Intelligence
- **IOC Management**: Dynamic indicator indexing, enrichment loops, and lifecycle tracking.
- **Campaign Tracking**: Maps campaign objects to active threat actors and associated MITRE ATT&CK vectors.
- **Threat Actors**: Attributes indicators and correlation patterns to known adversary profiles.
- **Correlation Engine**: Real-time correlation loops mapping patterns to ATT&CK matrix.

### Detection Engineering
- **Sigma Rules**: Ingest and test structured endpoint detection rules.
- **YARA Rules**: Run network/file signature matching and track performance.
- **Detection Analytics**: Evaluate rules for drift, precision, recall, and false-positive rates.

### SOC Operations
- **Alerts & Cases**: Fully featured incident workflow workbench.
- **SOAR Automation**: Trigger response playbooks with human-in-the-loop approvals.
- **Timeline Logs**: Visual chronology of alert progression.

### Intelligence Sharing
- **STIX 2.1**: Standards-compliant export of indicators and relations.
- **TAXII**: Automated sharing client supporting collection sync.
- **MISP**: Idempotent MISP event synchronization.

### SIEM & EDR Integration
- Log source connector integration with **Splunk, Microsoft Sentinel, Elastic Security, QRadar, and Google Chronicle**.
- Endpoint agent telemetry tracking with CrowdStrike and Defender.

### AI Platform
- **Security Copilot**: Grounded RAG-based analyst chatbot.
- **Knowledge Graph**: Node-relationship mappings with community clustering.
- **Natural Language Threat Hunting**: Translates natural language questions to SQL filters.

---

## Architecture

```text
       React 19 Frontend (Tailwind v4)
                    ↓
        FastAPI API Gateway (Port 8000)
       ↙            ↓            ↘
PostgreSQL     Redis Cache     Kafka Stream
    ↑               ↑               ↓
    ↖_________ Celery Worker ________↙
```

---

## Tech Stack

### Backend
- **Core**: FastAPI, Python 3.10
- **Database**: SQLAlchemy ORM, PostgreSQL
- **Caching**: Redis
- **Message Broker & Queue**: Kafka, Zookeeper, Celery

### Frontend
- **Framework**: React 19, TypeScript, Vite
- **Styling**: Tailwind CSS v4 (dark mode default)
- **Visuals**: Recharts (metric charts), React Flow (graph view)
- **Data Fetching**: Axios, TanStack Query

---

## Local Setup

1. **Install Python Dependencies**:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. **Build and Start Platform Services**:
   ```bash
   docker-compose up --build -d
   ```
3. **Start Frontend Workspace**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

---

## Running Tests

### Backend Tests
```powershell
.venv\Scripts\python -m pytest --cov=src --cov-report=term-missing
```

### Frontend Tests
```powershell
cd frontend
npm run test
```

---

## License
MIT
