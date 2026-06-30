import { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, Briefcase, TrendingUp, Cpu, Search, Database, 
  Map, CheckSquare, BarChart2, User, Settings, Eye, Play, Plus
} from 'lucide-react';
import { 
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, 
  PieChart, Pie, Cell
} from 'recharts';
import ReactFlow, { Background } from 'reactflow';
import 'reactflow/dist/style.css';

import { 
  getSocDashboard, getThreatIntelligence, getGraphData, sendCopilotMessage, 
  translateQuery, getDetections, getComplianceSnapshots, getExposureScore 
} from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [role, setRole] = useState('ANALYST');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // Global States
  const [stats, setStats] = useState<any>({
    open_alerts: 14,
    critical_alerts: 3,
    active_cases: 6,
    mtta_minutes: 4.8,
    mttr_minutes: 38.2,
    detection_coverage_pct: 78.5,
    alert_fidelity_score: 82.0,
    threat_score: 42.5,
    ai_cost_today: 0.85
  });
  const [iocs, setIocs] = useState<any[]>([
    { id: 1, indicator_type: 'DOMAIN', indicator_value: 'phish-verify.net', severity: 'HIGH', campaign: 'TA505' },
    { id: 2, indicator_type: 'IP', indicator_value: '198.51.100.42', severity: 'CRITICAL', campaign: 'APT29' }
  ]);
  const [graphData, setGraphData] = useState<any>({
    entities: [
      { id: 1, entity_type: 'Actor', entity_name: 'APT29' },
      { id: 2, entity_type: 'Campaign', entity_name: 'Cozy Bear' },
      { id: 3, entity_type: 'IOC', entity_name: '198.51.100.42' }
    ],
    relationships: [
      { id: 1, source_entity_id: 1, target_entity_id: 2, relationship_type: 'attributed-to' },
      { id: 2, source_entity_id: 3, target_entity_id: 2, relationship_type: 'indicates' }
    ]
  });
  const [detections, setDetections] = useState<any[]>([
    { id: 1, name: 'Cmdline execution matcher', rule_type: 'YARA', enabled: true },
    { id: 2, name: 'Registry alter detector', rule_type: 'SIGMA', enabled: true }
  ]);
  const [compliance, setCompliance] = useState<any[]>([
    { id: 1, framework: 'NIST_CSF', compliance_score: 72.5 },
    { id: 2, framework: 'CIS_CONTROLS', compliance_score: 80.0 }
  ]);
  const [exposure, setExposure] = useState<any>({
    critical_assets: 2,
    high_risk_assets: 5,
    active_campaigns: 1,
    active_actors: 3,
    critical_alerts: 4,
    exposure_score: 42.5
  });

  // Drawer State
  const [drawerEntity, setDrawerEntity] = useState<any>(null);

  // Copilot State
  const [messages, setMessages] = useState<any[]>([
    { role: 'assistant', content: 'Welcome to Security Copilot. Ask me anything about the active campaign or IOC indicator.' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [confidenceTrend, setConfidenceTrend] = useState(85);
  const [validationScore, setValidationScore] = useState(1.0);

  // Hunting State
  const [nlQuery, setNlQuery] = useState('');
  const [translatedSql, setTranslatedSql] = useState('');
  const [huntHistory, setHuntHistory] = useState<string[]>([]);

  // Detection Editor State
  const [selectedRule, setSelectedRule] = useState<any>(null);
  const [ruleCode, setRuleCode] = useState('');

  // Timeline / Workbench State
  const [timelineEvents] = useState([
    { time: '2026-06-30 04:15', title: 'Suspicious IP Connection', desc: 'Endpoint WKS-99 made network connection to malicious domain.' },
    { time: '2026-06-30 04:30', title: 'Credential Dumping Detected', desc: 'LSASS memory read matching MITRE T1003.' }
  ]);
  const [analystNotes, setAnalystNotes] = useState('');

  // Initial Seed & Load
  useEffect(() => {
    async function loadAll() {
      const d1 = await getSocDashboard();
      const d2 = await getThreatIntelligence();
      const d3 = await getGraphData();
      const d4 = await getDetections();
      const d5 = await getComplianceSnapshots();
      const d6 = await getExposureScore();

      setStats(d1);
      setIocs(d2);
      setGraphData(d3);
      setDetections(d4);
      setCompliance(d5);
      setExposure(d6);
    }
    loadAll();
  }, []);

  const handleCopilotSend = async () => {
    if (!chatInput.trim()) return;
    const userMsg = chatInput;
    setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setChatInput('');

    const res = await sendCopilotMessage(1, userMsg);
    setMessages(prev => [...prev, { role: 'assistant', content: res.response }]);
    setConfidenceTrend(res.confidence_score);
    setValidationScore(res.validation_status === 'PASS' ? 1.0 : 0.6);
  };

  const handleHuntTranslate = async () => {
    if (!nlQuery.trim()) return;
    const res = await translateQuery(nlQuery);
    setTranslatedSql(res.generated_query);
    setHuntHistory(prev => [nlQuery, ...prev]);
  };

  // Recharts color palette
  const COLORS = ['#8b5cf6', '#ef4444', '#10b981', '#f59e0b'];

  return (
    <div className="flex h-screen bg-[#090a0f] text-[#f3f4f6] font-sans">
      {/* Sidebar */}
      {sidebarOpen && (
        <aside className="w-64 bg-[#12131a] border-r border-[#1f2937] flex flex-col justify-between">
          <div>
            <div className="p-6 flex items-center space-x-3 border-b border-[#1f2937]">
              <Shield className="h-8 w-8 text-[#8b5cf6] filter drop-shadow-[0_0_8px_rgba(139,92,246,0.5)]" />
              <span className="font-semibold text-lg tracking-wider">CTI Platform</span>
            </div>
            <nav className="p-4 space-y-1">
              {[
                { id: 'dashboard', label: 'SOC Dashboard', icon: BarChart2 },
                { id: 'threat-intelligence', label: 'Threat Intel', icon: Database },
                { id: 'graph', label: 'Graph Explorer', icon: Map },
                { id: 'copilot', label: 'Copilot Chat', icon: Cpu },
                { id: 'hunting', label: 'Hunting Studio', icon: Search },
                { id: 'cases', label: 'Investigation', icon: Briefcase },
                { id: 'detections', label: 'Detections', icon: AlertTriangle },
                { id: 'compliance', label: 'Compliance', icon: CheckSquare }
              ].map(item => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm transition-all duration-150 ${activeTab === item.id ? 'bg-[#8b5cf6]/20 text-[#8b5cf6] border-l-4 border-[#8b5cf6] font-medium' : 'text-[#9ca3af] hover:bg-[#12131a]/80 hover:text-white'}`}
                  >
                    <Icon className="h-5 w-5" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          {/* User Settings & Roles switcher */}
          <div className="p-4 border-t border-[#1f2937] space-y-3">
            <div className="flex items-center justify-between text-xs text-[#9ca3af]">
              <span>Active Role:</span>
              <select 
                value={role} 
                onChange={(e) => setRole(e.target.value)}
                className="bg-[#12131a] border border-[#1f2937] text-white px-2 py-1 rounded cursor-pointer"
              >
                <option value="ADMIN">Admin</option>
                <option value="ANALYST">Analyst</option>
                <option value="VIEWER">Viewer</option>
              </select>
            </div>
            <div className="flex items-center space-x-3 text-sm">
              <User className="h-5 w-5 text-[#8b5cf6]" />
              <span>{role === 'ADMIN' ? 'Alice Admin' : 'Bob Analyst'}</span>
            </div>
          </div>
        </aside>
      )}

      {/* Main Panel */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Global Intelligence Banner */}
        <header className="h-16 bg-[#12131a] border-b border-[#1f2937] flex items-center justify-between px-8">
          <div className="flex items-center space-x-6 text-sm">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              <span>Alerts: <strong className="text-red-500">{stats.critical_alerts || 0} Critical</strong> / {stats.open_alerts || 0} Open</span>
            </div>
            <div className="flex items-center space-x-2 border-l border-[#1f2937] pl-6">
              <Briefcase className="h-4 w-4 text-yellow-500" />
              <span>Active Cases: <strong>{stats.active_cases || 0}</strong></span>
            </div>
            <div className="flex items-center space-x-2 border-l border-[#1f2937] pl-6">
              <TrendingUp className="h-4 w-4 text-purple-400" />
              <span>Threat Score: <strong className="text-purple-400">{exposure.exposure_score || 42.5}</strong></span>
            </div>
            <div className="flex items-center space-x-2 border-l border-[#1f2937] pl-6">
              <CheckSquare className="h-4 w-4 text-green-400" />
              <span>Coverage: <strong>{stats.detection_coverage_pct || 78.5}%</strong></span>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <span className="text-xs bg-[#1f2937] text-gray-300 px-3 py-1.5 rounded-full font-mono">Cost Today: ${stats.ai_cost_today || 0.85}</span>
            <button onClick={() => setSidebarOpen(!sidebarOpen)} className="text-gray-400 hover:text-white p-2 rounded">
              <Settings className="h-5 w-5" />
            </button>
          </div>
        </header>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-8">
          
          {/* Dashboard Tab */}
          {activeTab === 'dashboard' && (
            <div className="space-y-8">
              {/* Stat Cards */}
              <div className="grid grid-cols-4 gap-6">
                {[
                  { label: 'MTTA', value: `${stats.mtta_minutes || 4.8}m`, desc: 'Mean Time to Acknowledge', color: 'border-purple-500' },
                  { label: 'MTTR', value: `${stats.mttr_minutes || 38.2}m`, desc: 'Mean Time to Remediate', color: 'border-red-500' },
                  { label: 'Asset Risk score', value: 'High (80)', desc: 'avg critical endpoints risk', color: 'border-yellow-500' },
                  { label: 'Alert Fidelity', value: `${stats.alert_fidelity_score || 82.0}%`, desc: 'ratio of true positive cases', color: 'border-green-500' }
                ].map((c, i) => (
                  <div key={i} className={`bg-[#12131a] p-6 rounded-xl border-l-4 ${c.color} shadow-lg transition-transform hover:-translate-y-1`}>
                    <h4 className="text-[#9ca3af] text-sm font-medium">{c.label}</h4>
                    <h2 className="text-3xl font-bold mt-2">{c.value}</h2>
                    <p className="text-xs text-[#9ca3af] mt-1">{c.desc}</p>
                  </div>
                ))}
              </div>

              {/* Charts grid */}
              <div className="grid grid-cols-2 gap-8">
                <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937] shadow-xl">
                  <h3 className="font-semibold text-lg mb-6">Alert Trend & Volumes</h3>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={[
                        { name: 'Mon', alerts: 12, cases: 4 },
                        { name: 'Tue', alerts: 19, cases: 6 },
                        { name: 'Wed', alerts: 15, cases: 5 },
                        { name: 'Thu', alerts: 24, cases: 8 },
                        { name: 'Fri', alerts: 18, cases: 6 },
                        { name: 'Sat', alerts: 10, cases: 3 },
                        { name: 'Sun', alerts: 14, cases: 6 }
                      ]}>
                        <defs>
                          <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.8}/>
                            <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                        <XAxis dataKey="name" stroke="#9ca3af" />
                        <YAxis stroke="#9ca3af" />
                        <Tooltip contentStyle={{ backgroundColor: '#12131a', borderColor: '#1f2937' }} />
                        <Area type="monotone" dataKey="alerts" stroke="#8b5cf6" fillOpacity={1} fill="url(#colorAlerts)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937] shadow-xl">
                  <h3 className="font-semibold text-lg mb-6">Severity Distribution</h3>
                  <div className="h-64 flex items-center justify-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={[
                            { name: 'Critical', value: 3 },
                            { name: 'High', value: 5 },
                            { name: 'Medium', value: 4 },
                            { name: 'Low', value: 2 }
                          ]}
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={5}
                          dataKey="value"
                        >
                          {COLORS.map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#12131a', borderColor: '#1f2937' }} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="space-y-2">
                      <div className="flex items-center space-x-2 text-xs">
                        <span className="h-3 w-3 rounded-full bg-[#8b5cf6]"></span>
                        <span>Critical</span>
                      </div>
                      <div className="flex items-center space-x-2 text-xs">
                        <span className="h-3 w-3 rounded-full bg-[#ef4444]"></span>
                        <span>High</span>
                      </div>
                      <div className="flex items-center space-x-2 text-xs">
                        <span className="h-3 w-3 rounded-full bg-[#10b981]"></span>
                        <span>Medium</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Threat Intel Explorer Tab */}
          {activeTab === 'threat-intelligence' && (
            <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937] shadow-xl">
              <div className="flex items-center justify-between mb-6">
                <h3 className="font-semibold text-lg">Active Indicators of Compromise (IOCs)</h3>
                <div className="flex items-center space-x-4">
                  <button className="bg-[#8b5cf6] hover:bg-[#8b5cf6]/80 text-white px-4 py-2 rounded-lg text-sm flex items-center space-x-2">
                    <Plus className="h-4 w-4" />
                    <span>Add Indicator</span>
                  </button>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-[#1f2937] text-[#9ca3af]">
                      <th className="py-3 px-4">Type</th>
                      <th className="py-3 px-4">Indicator Value</th>
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4">Campaign</th>
                      <th className="py-3 px-4">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.map(ioc => (
                      <tr key={ioc.id} className="border-b border-[#1f2937] hover:bg-[#12131a]/80">
                        <td className="py-3 px-4 font-mono text-sm">{ioc.indicator_type}</td>
                        <td className="py-3 px-4">{ioc.indicator_value}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 rounded text-xs ${ioc.severity === 'CRITICAL' ? 'bg-red-900/40 text-red-400' : 'bg-orange-900/40 text-orange-400'}`}>
                            {ioc.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-[#8b5cf6]">{ioc.campaign}</td>
                        <td className="py-3 px-4">
                          <button onClick={() => setDrawerEntity(ioc)} className="text-gray-400 hover:text-white flex items-center space-x-1">
                            <Eye className="h-4 w-4" />
                            <span>View</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Graph Explorer Tab */}
          {activeTab === 'graph' && (
            <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937] shadow-xl flex flex-col h-[600px]">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold text-lg">Security Knowledge Graph</h3>
                <div className="flex space-x-3 text-xs">
                  <span className="px-3 py-1.5 rounded-full bg-purple-900/40 text-purple-400 border border-purple-800">Blast Radius Active</span>
                  <span className="px-3 py-1.5 rounded-full bg-blue-900/40 text-blue-400 border border-blue-800">Louvain Communities</span>
                </div>
              </div>
              <div className="flex-1 bg-[#090a0f] rounded-lg border border-[#1f2937] overflow-hidden">
                <ReactFlow 
                  nodes={graphData.entities.map((e: any, i: number) => ({
                    id: e.id.toString(),
                    position: { x: 100 + i * 150, y: 150 + (i % 2) * 100 },
                    data: { label: `${e.entity_type}: ${e.entity_name}` },
                    style: { background: '#12131a', color: '#f3f4f6', border: '1px solid #8b5cf6', borderRadius: 8 }
                  }))}
                  edges={graphData.relationships.map((r: any) => ({
                    id: r.id.toString(),
                    source: r.source_entity_id.toString(),
                    target: r.target_entity_id.toString(),
                    label: r.relationship_type,
                    animated: true
                  }))}
                >
                  <Background color="#1f2937" gap={16} />
                </ReactFlow>
              </div>
            </div>
          )}

          {/* Copilot Chat Tab */}
          {activeTab === 'copilot' && (
            <div className="grid grid-cols-3 gap-8 h-[600px]">
              {/* Chat Column */}
              <div className="col-span-2 bg-[#12131a] rounded-xl border border-[#1f2937] shadow-xl flex flex-col justify-between">
                <div className="p-6 border-b border-[#1f2937] flex items-center justify-between">
                  <h3 className="font-semibold text-lg flex items-center space-x-2">
                    <Cpu className="h-5 w-5 text-[#8b5cf6]" />
                    <span>Copilot Chat Workspace</span>
                  </h3>
                  <span className="text-xs bg-[#1f2937] px-2 py-1 rounded">Model: GPT-4o</span>
                </div>
                <div className="flex-1 overflow-y-auto p-6 space-y-4">
                  {messages.map((m, i) => (
                    <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                      <div className={`p-4 rounded-xl max-w-lg text-sm ${m.role === 'user' ? 'bg-[#8b5cf6] text-white' : 'bg-[#1f2937] text-gray-200'}`}>
                        {m.content}
                      </div>
                    </div>
                  ))}
                </div>
                <div className="p-4 border-t border-[#1f2937] flex items-center space-x-3">
                  <input
                    type="text"
                    placeholder="Ask about active alerts or hunting..."
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    className="flex-1 bg-[#090a0f] border border-[#1f2937] rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-[#8b5cf6]"
                  />
                  <button onClick={handleCopilotSend} className="bg-[#8b5cf6] hover:bg-[#8b5cf6]/80 text-white px-5 py-3 rounded-lg text-sm font-medium">
                    Send
                  </button>
                </div>
              </div>

              {/* Side Panels */}
              <div className="space-y-6">
                <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937]">
                  <h4 className="font-semibold mb-4 text-sm text-[#9ca3af]">Grounding Validation</h4>
                  <div className="space-y-4">
                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span>Confidence Score</span>
                        <span>{confidenceTrend}%</span>
                      </div>
                      <div className="w-full bg-[#1f2937] h-2 rounded-full overflow-hidden">
                        <div className="bg-[#8b5cf6] h-full" style={{ width: `${confidenceTrend}%` }}></div>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span>Hallucination Prevention Score</span>
                        <span>{validationScore * 100}%</span>
                      </div>
                      <div className="w-full bg-[#1f2937] h-2 rounded-full overflow-hidden">
                        <div className="bg-green-500 h-full" style={{ width: `${validationScore * 100}%` }}></div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937] space-y-3">
                  <h4 className="font-semibold text-sm text-[#9ca3af]">Retrieved Evidences</h4>
                  <div className="p-3 bg-[#090a0f] rounded-lg border border-[#1f2937] text-xs">
                    <p className="text-[#8b5cf6] font-semibold mb-1">Evidence ID: #1</p>
                    <p className="text-gray-300 font-mono">APT29 attribute: Cozy Bear indications</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Hunting Studio Tab */}
          {activeTab === 'hunting' && (
            <div className="space-y-8">
              <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937]">
                <h3 className="font-semibold text-lg mb-6">Threat Hunting Natural Language Query Sandbox</h3>
                <div className="flex items-center space-x-4 mb-6">
                  <input
                    type="text"
                    placeholder="e.g. Show domains associated with APT28"
                    value={nlQuery}
                    onChange={(e) => setNlQuery(e.target.value)}
                    className="flex-1 bg-[#090a0f] border border-[#1f2937] rounded-lg px-4 py-3 text-sm focus:outline-none"
                  />
                  <button onClick={handleHuntTranslate} className="bg-[#8b5cf6] hover:bg-[#8b5cf6]/80 text-white px-6 py-3 rounded-lg text-sm flex items-center space-x-2">
                    <Play className="h-4 w-4" />
                    <span>Translate Query</span>
                  </button>
                </div>

                {translatedSql && (
                  <div className="p-4 bg-[#090a0f] rounded-lg border border-[#1f2937] space-y-2">
                    <h4 className="text-xs text-[#8b5cf6] font-semibold tracking-wider">GENERATED SQL QUERY</h4>
                    <pre className="text-xs text-[#9ca3af] font-mono whitespace-pre-wrap">{translatedSql}</pre>
                  </div>
                )}
              </div>

              {huntHistory.length > 0 && (
                <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937]">
                  <h4 className="font-semibold text-sm mb-4 text-[#9ca3af]">Translation Audit Logs</h4>
                  <div className="space-y-2">
                    {huntHistory.map((q, i) => (
                      <div key={i} className="flex items-center justify-between text-xs p-3 bg-[#090a0f] rounded border border-[#1f2937]">
                        <span className="font-mono text-gray-300">{q}</span>
                        <span className="px-2 py-0.5 rounded bg-green-900/40 text-green-400">PASSED</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Case workbench Tab */}
          {activeTab === 'cases' && (
            <div className="grid grid-cols-3 gap-8">
              {/* Timeline Workbench */}
              <div className="col-span-2 bg-[#12131a] p-6 rounded-xl border border-[#1f2937] space-y-6">
                <h3 className="font-semibold text-lg">Case Workbench: Compromised Host WKS-99</h3>
                
                <div className="relative border-l-2 border-[#1f2937] pl-6 ml-4 space-y-6">
                  {timelineEvents.map((ev, i) => (
                    <div key={i} className="relative">
                      <span className="absolute -left-8 top-1.5 bg-[#8b5cf6] h-4.5 w-4.5 rounded-full border-4 border-[#12131a]"></span>
                      <p className="text-xs text-[#8b5cf6] font-mono">{ev.time}</p>
                      <h4 className="font-semibold text-sm mt-1">{ev.title}</h4>
                      <p className="text-xs text-gray-400 mt-1">{ev.desc}</p>
                    </div>
                  ))}
                </div>

                <div className="border-t border-[#1f2937] pt-6 space-y-4">
                  <h4 className="font-semibold text-sm">Analyst Investigation Notes</h4>
                  <textarea
                    rows={4}
                    value={analystNotes}
                    onChange={(e) => setAnalystNotes(e.target.value)}
                    placeholder="Record notes on active remediation..."
                    className="w-full bg-[#090a0f] border border-[#1f2937] rounded-lg p-4 text-sm focus:outline-none"
                  ></textarea>
                </div>
              </div>

              {/* Sidebar recommendations */}
              <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937] space-y-6">
                <h4 className="font-semibold text-sm text-[#9ca3af]">AI Incident Recommendations</h4>
                <div className="space-y-4">
                  <div className="p-4 bg-yellow-950/40 border border-yellow-800/40 rounded-lg text-xs">
                    <p className="font-semibold text-yellow-400 mb-1">Remediation Action Suggested</p>
                    <p className="text-gray-300">Isolate WKS-99 and disable compromised domain controller user admin rights.</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Detections Tab */}
          {activeTab === 'detections' && (
            <div className="space-y-8">
              <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937]">
                <h3 className="font-semibold text-lg mb-6">Detection Rule Catalog</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="border-b border-[#1f2937] text-[#9ca3af]">
                        <th className="py-3 px-4">Rule Name</th>
                        <th className="py-3 px-4">Type</th>
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detections.map(rule => (
                        <tr key={rule.id} className="border-b border-[#1f2937] hover:bg-[#12131a]/80">
                          <td className="py-3 px-4">{rule.name}</td>
                          <td className="py-3 px-4 font-mono text-sm">{rule.rule_type}</td>
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 rounded text-xs bg-green-900/40 text-green-400">ACTIVE</span>
                          </td>
                          <td className="py-3 px-4">
                            <button 
                              onClick={() => {
                                setSelectedRule(rule);
                                setRuleCode(rule.rule_type === 'YARA' ? 'rule Yara_Rule { ... }' : 'title: Sigma_Rule');
                              }} 
                              className="text-[#8b5cf6] hover:underline text-sm"
                            >
                              Edit Rule
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {selectedRule && (
                <div className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937] space-y-4">
                  <h4 className="font-semibold text-sm">Editor: {selectedRule.name}</h4>
                  <textarea
                    rows={8}
                    value={ruleCode}
                    onChange={(e) => setRuleCode(e.target.value)}
                    className="w-full bg-[#090a0f] border border-[#1f2937] rounded-lg p-4 font-mono text-xs focus:outline-none"
                  ></textarea>
                  <button className="bg-[#8b5cf6] text-white px-4 py-2 rounded text-xs">Save Changes</button>
                </div>
              )}
            </div>
          )}

          {/* Compliance Tab */}
          {activeTab === 'compliance' && (
            <div className="space-y-8">
              <div className="grid grid-cols-2 gap-8">
                {compliance.map(c => (
                  <div key={c.id} className="bg-[#12131a] p-6 rounded-xl border border-[#1f2937]">
                    <h4 className="font-semibold text-lg text-[#8b5cf6]">{c.framework} Mapping</h4>
                    <h2 className="text-4xl font-bold mt-4">{c.compliance_score}%</h2>
                    <p className="text-xs text-[#9ca3af] mt-2">Compliance Score mapping based on active detection rules.</p>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      </main>

      {/* Universal Drawer */}
      {drawerEntity && (
        <div className="fixed inset-y-0 right-0 w-96 bg-[#12131a] border-l border-[#1f2937] shadow-2xl p-8 overflow-y-auto z-50">
          <div className="flex items-center justify-between border-b border-[#1f2937] pb-4 mb-6">
            <h3 className="font-semibold text-lg">Entity Details</h3>
            <button onClick={() => setDrawerEntity(null)} className="text-gray-400 hover:text-white">Close</button>
          </div>
          <div className="space-y-6 text-sm">
            <div>
              <label className="text-xs text-[#9ca3af] uppercase">Type</label>
              <p className="font-mono mt-1 text-[#8b5cf6]">{drawerEntity.indicator_type || 'Unknown'}</p>
            </div>
            <div>
              <label className="text-xs text-[#9ca3af] uppercase">Value</label>
              <p className="font-semibold mt-1">{drawerEntity.indicator_value || 'None'}</p>
            </div>
            <div>
              <label className="text-xs text-[#9ca3af] uppercase">Severity</label>
              <p className="mt-1 text-red-400">{drawerEntity.severity || 'Medium'}</p>
            </div>
            <div>
              <label className="text-xs text-[#9ca3af] uppercase">Campaign / Context</label>
              <p className="mt-1 text-gray-300">{drawerEntity.campaign || 'No campaigns connected'}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
