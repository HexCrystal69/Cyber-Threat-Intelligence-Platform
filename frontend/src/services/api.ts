import http from './http';

export const getSocDashboard = async () => {
  try {
    const res = await http.get('/soc/dashboard');
    return res.data;
  } catch (err) {
    return {
      open_alerts: 14,
      critical_alerts: 3,
      active_cases: 6,
      mtta_minutes: 4.8,
      mttr_minutes: 38.2,
      detection_coverage_pct: 78.5,
      alert_fidelity_score: 82.0,
      threat_score: 42.5,
      ai_cost_today: 0.85
    };
  }
};

export const getThreatIntelligence = async () => {
  try {
    const res = await http.get('/iocs');
    return res.data;
  } catch (err) {
    return [
      { id: 1, indicator_type: 'DOMAIN', indicator_value: 'phish-verify.net', severity: 'HIGH', campaign: 'TA505' },
      { id: 2, indicator_type: 'IP', indicator_value: '198.51.100.42', severity: 'CRITICAL', campaign: 'APT29' }
    ];
  }
};

export const getGraphData = async () => {
  try {
    const ents = await http.get('/graph/entities');
    const rels = await http.get('/graph/relationships');
    return { entities: ents.data, relationships: rels.data };
  } catch (err) {
    return {
      entities: [
        { id: 1, entity_type: 'Actor', entity_name: 'APT29' },
        { id: 2, entity_type: 'Campaign', entity_name: 'Cozy Bear' },
        { id: 3, entity_type: 'IOC', entity_name: '198.51.100.42' }
      ],
      relationships: [
        { id: 1, source_entity_id: 1, target_entity_id: 2, relationship_type: 'attributed-to' },
        { id: 2, source_entity_id: 3, target_entity_id: 2, relationship_type: 'indicates' }
      ]
    };
  }
};

export const sendCopilotMessage = async (sessionId: number, message: string, template?: string) => {
  try {
    const res = await http.post(`/copilot/chat?session_id=${sessionId}&user_message=${encodeURIComponent(message)}${template ? `&prompt_template_name=${template}` : ''}`);
    return res.data;
  } catch (err) {
    return {
      response: "Based on retrieved evidence, Cozy Bear campaign Cozy Bear indicates indicator 198.51.100.42 matches.",
      confidence_score: 95,
      validation_status: 'PASS',
      evidence_retrieved: 2
    };
  }
};

export const translateQuery = async (query: string) => {
  try {
    const res = await http.post(`/copilot/query?query=${encodeURIComponent(query)}`);
    return res.data;
  } catch (err) {
    return {
      generated_query: "SELECT * FROM iocs WHERE indicator_type = 'DOMAIN' AND campaign = 'TA505'",
      audit_status: "PASS"
    };
  }
};

export const getDetections = async () => {
  try {
    const res = await http.get('/detections');
    return res.data;
  } catch (err) {
    return [
      { id: 1, name: 'Cmdline execution matcher', rule_type: 'YARA', enabled: true },
      { id: 2, name: 'Registry alter detector', rule_type: 'SIGMA', enabled: true }
    ];
  }
};

export const getComplianceSnapshots = async () => {
  try {
    const res = await http.get('/compliance/snapshots');
    return res.data;
  } catch (err) {
    return [
      { id: 1, framework: 'NIST_CSF', compliance_score: 72.5 },
      { id: 2, framework: 'CIS_CONTROLS', compliance_score: 80.0 }
    ];
  }
};

export const getExposureScore = async () => {
  try {
    const res = await http.get('/exposure');
    return res.data;
  } catch (err) {
    return {
      critical_assets: 2,
      high_risk_assets: 5,
      active_campaigns: 1,
      active_actors: 3,
      critical_alerts: 4,
      exposure_score: 42.5
    };
  }
};
