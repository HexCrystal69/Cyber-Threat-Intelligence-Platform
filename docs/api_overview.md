# API Overview Documentation

The platform exposes REST APIs through FastAPI, grouped by feature area:

## Endpoints Summary

### 1. Threat Intelligence
- `GET /api/v1/iocs`: Fetch active indicators of compromise.
- `POST /api/v1/iocs`: Ingest new threat indicator.

### 2. AI Security Copilot
- `POST /api/v1/copilot/chat`: Grounded chat with RAG evidence validation.
- `POST /api/v1/copilot/query`: Natural language to SQL query translator.

### 3. Knowledge Graph
- `GET /api/v1/graph/entities`: List entities (Actors, IOCs, Campaigns).
- `GET /api/v1/graph/path`: Shortest path traversal analytics.
- `GET /api/v1/graph/communities`: Community clustering.

### 4. SIEM & EDR Management
- `GET /api/v1/siem/connectors`: List Splunk/Sentinel log source connectors.
- `GET /api/v1/endpoints`: Retrieve active EDR endpoints and risk scores.
