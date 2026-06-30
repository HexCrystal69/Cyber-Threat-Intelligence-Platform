from prometheus_client import Counter, Histogram

# Ingested IOC count
ioc_ingested_total = Counter(
    "ioc_ingested_total",
    "Total number of successfully ingested indicators of compromise",
    ["feed_name", "indicator_type"]
)

# Failed IOC count
ioc_failed_total = Counter(
    "ioc_failed_total",
    "Total number of failed indicator of compromise records",
    ["feed_name", "reason"]
)

# Ingestion jobs count
ingestion_jobs_total = Counter(
    "ingestion_jobs_total",
    "Total number of ingestion job executions",
    ["feed_name", "status"]
)

# Ingestion duration
ingestion_duration_seconds = Histogram(
    "ingestion_duration_seconds",
    "Time spent executing feed ingestion in seconds",
    ["feed_name"]
)

# STIX bundles generated
stix_bundles_generated_total = Counter(
    "stix_bundles_generated_total",
    "Total number of STIX bundles generated"
)

# TAXII sync operations
taxii_sync_total = Counter(
    "taxii_sync_total",
    "Total number of TAXII sync operations executed",
    ["collection_id", "sync_type"]
)

# MISP sync jobs
misp_sync_total = Counter(
    "misp_sync_total",
    "Total number of MISP sync jobs executed",
    ["instance_name"]
)

# Response executions
response_executions_total = Counter(
    "response_executions_total",
    "Total number of response executions run",
    ["response_type", "status"]
)

# Threat sharing events
threat_sharing_events_total = Counter(
    "threat_sharing_events_total",
    "Total threat intelligence sharing events",
    ["partner_id", "action_type"]
)

# SIEM events ingested
siem_events_ingested_total = Counter(
    "siem_events_ingested_total",
    "Total number of SIEM events ingested",
    ["connector_type"]
)

# EDR assets total
edr_assets_total = Counter(
    "edr_assets_total",
    "Total number of EDR assets discovered"
)

# EDR detections total
edr_detections_total = Counter(
    "edr_detections_total",
    "Total number of EDR detections synced"
)

# Security events total
security_events_total = Counter(
    "security_events_total",
    "Total security events in data lake"
)

# Attack simulations total
attack_simulations_total = Counter(
    "attack_simulations_total",
    "Total attack simulations run"
)

# Coverage gaps total
coverage_gaps_total = Counter(
    "coverage_gaps_total",
    "Total coverage gaps identified"
)

# Compliance snapshots total
compliance_snapshots_total = Counter(
    "compliance_snapshots_total",
    "Total compliance snapshots generated"
)

# Alert fidelity score
alert_fidelity_score = Counter(
    "alert_fidelity_score_total",
    "Aggregated alert fidelity score stats"
)

# Copilot Requests
copilot_requests_total = Counter(
    "copilot_requests_total",
    "Total Copilot requests run"
)

# Copilot Tokens
copilot_tokens_total = Counter(
    "copilot_tokens_total",
    "Total Copilot tokens consumed"
)

# RAG Queries
rag_queries_total = Counter(
    "rag_queries_total",
    "Total RAG queries executed"
)

# Documents Embedded
documents_embedded_total = Counter(
    "documents_embedded_total",
    "Total documents embedded"
)

# Graph Nodes
graph_nodes_total = Counter(
    "graph_nodes_total",
    "Total nodes in knowledge graph"
)

# Graph Edges
graph_edges_total = Counter(
    "graph_edges_total",
    "Total edges in knowledge graph"
)

# AI Validation Runs
ai_validation_runs_total = Counter(
    "ai_validation_runs_total",
    "Total AI responses validated"
)

# AI Supported Claims
ai_supported_claims_total = Counter(
    "ai_supported_claims_total",
    "Total supported claims from AI"
)

# AI Unsupported Claims
ai_unsupported_claims_total = Counter(
    "ai_unsupported_claims_total",
    "Total unsupported claims from AI"
)
