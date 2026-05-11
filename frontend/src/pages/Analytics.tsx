import { useState, useEffect } from 'react';
import { http as axios } from '../api/client';
import { PieChart, Pie, Cell, BarChart, Bar, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faChartLine,
    faDatabase,
    faTriangleExclamation,
    faShieldHalved,
    faToolbox,
    faClock,
    faServer,
    faFilePdf,
    faFileCode
} from '@fortawesome/free-solid-svg-icons';

interface McpStats {
    total_calls: number;
    tools: { name: string; calls: number; success_rate: number }[];
    hourly_usage: number[];
}

interface IngestionData {
    total_7d_gb: number;
    top_tables: { table: string; size_gb: number }[];
}

interface IncidentStats {
    status: { open: number; closed: number };
    severity: { high: number; medium: number; low: number; informational: number };
}

interface PostureData {
    score: number;
    max_score: number;
    categories: { name: string; score: number; weight: number }[];
    recommendations: { task: string; impact: string; severity: string }[];
}

export default function Analytics() {
    const [tab, setTab] = useState<'overview' | 'mcp' | 'ingestion'>('overview');
    const [days, setDays] = useState(7);
    const [mcp, setMcp] = useState<McpStats | null>(null);
    const [ingestion, setIngestion] = useState<IngestionData | null>(null);
    const [incidents, setIncidents] = useState<IncidentStats | null>(null);
    const [posture, setPosture] = useState<PostureData | null>(null);
    const [loading, setLoading] = useState(true);
    const [isExporting, setIsExporting] = useState(false);

    const handleExport = async (format: 'pdf' | 'html') => {
        if (!mcp || !ingestion || !incidents) return;
        setIsExporting(true);

        try {
            const reportHtml = `
                <div style="font-family: 'Inter', sans-serif; padding: 40px; color: #2D2D2D;">
                    <div style="display: flex; justify-content: space-between; border-bottom: 3px solid #D04A02; padding-bottom: 20px; margin-bottom: 30px;">
                        <div>
                            <h1 style="margin: 0; font-size: 28px; color: #D04A02;">Advanced Analytics Report</h1>
                            <p style="margin: 5px 0 0; color: #7D7D7D;">Sentinel Vigil · Powered by Microsoft Sentinel</p>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-weight: 700;">Time Horizon: Last ${days} Days</div>
                            <div style="font-size: 12px; color: #7D7D7D;">Generated: ${new Date().toLocaleString()}</div>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
                        <div style="background: #fdfdfd; border: 1px solid #E5E5E5; padding: 20px; border-radius: 8px;">
                            <h3 style="margin: 0 0 10px; font-size: 12px; text-transform: uppercase; color: #7D7D7D;">Security Posture Score</h3>
                            <div style="font-size: 32px; font-weight: 800; color: #D04A02;">${posture?.score}/${posture?.max_score}</div>
                        </div>
                        <div style="background: #fdfdfd; border: 1px solid #E5E5E5; padding: 20px; border-radius: 8px;">
                            <h3 style="margin: 0 0 10px; font-size: 12px; text-transform: uppercase; color: #7D7D7D;">Data Ingested</h3>
                            <div style="font-size: 32px; font-weight: 800; color: #2980B9;">${ingestion.total_7d_gb.toFixed(2)} GB</div>
                        </div>
                    </div>

                    <h2 style="border-left: 4px solid #D04A02; padding-left: 15px; margin: 40px 0 20px; font-size: 18px;">Incident Metrics</h2>
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 30px;">
                         <tr style="background: #F7F7F7;">
                            <th style="padding: 12px; text-align: left; border: 1px solid #E5E5E5;">Metric</th>
                            <th style="padding: 12px; text-align: left; border: 1px solid #E5E5E5;">Value</th>
                         </tr>
                         <tr><td style="padding: 12px; border: 1px solid #E5E5E5;">Open Incidents</td><td style="padding: 12px; border: 1px solid #E5E5E5; color: #C0392B; font-weight: 700;">${incidents.status.open}</td></tr>
                         <tr><td style="padding: 12px; border: 1px solid #E5E5E5;">Closed Incidents</td><td style="padding: 12px; border: 1px solid #E5E5E5;">${incidents.status.closed}</td></tr>
                         <tr><td style="padding: 12px; border: 1px solid #E5E5E5;">High Severity</td><td style="padding: 12px; border: 1px solid #E5E5E5; color: #C0392B;">${incidents.severity.high}</td></tr>
                         <tr><td style="padding: 12px; border: 1px solid #E5E5E5;">Medium Severity</td><td style="padding: 12px; border: 1px solid #E5E5E5; color: #E67E22;">${incidents.severity.medium}</td></tr>
                    </table>

                    <h2 style="border-left: 4px solid #D04A02; padding-left: 15px; margin: 40px 0 20px; font-size: 18px;">Top Ingestion Sources</h2>
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 30px;">
                        <tr style="background: #F7F7F7;">
                            <th style="padding: 12px; text-align: left; border: 1px solid #E5E5E5;">Table Name</th>
                            <th style="padding: 12px; text-align: left; border: 1px solid #E5E5E5;">Volume (GB)</th>
                            <th style="padding: 12px; text-align: left; border: 1px solid #E5E5E5;">Share (%)</th>
                        </tr>
                        ${ingestion.top_tables.map(t => `
                            <tr>
                                <td style="padding: 12px; border: 1px solid #E5E5E5; font-family: monospace;">${t.table}</td>
                                <td style="padding: 12px; border: 1px solid #E5E5E5; font-weight: 700;">${t.size_gb.toFixed(2)}</td>
                                <td style="padding: 12px; border: 1px solid #E5E5E5;">${((t.size_gb / ingestion.total_7d_gb) * 100).toFixed(1)}%</td>
                            </tr>
                        `).join('')}
                    </table>

                    <h2 style="border-left: 4px solid #D04A02; padding-left: 15px; margin: 40px 0 20px; font-size: 18px;">MCP Tool Activity</h2>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr style="background: #F7F7F7;">
                            <th style="padding: 12px; text-align: left; border: 1px solid #E5E5E5;">Tool</th>
                            <th style="padding: 12px; text-align: left; border: 1px solid #E5E5E5;">Total Calls</th>
                            <th style="padding: 12px; text-align: left; border: 1px solid #E5E5E5;">Success Rate</th>
                        </tr>
                        ${mcp.tools.map(t => `
                            <tr>
                                <td style="padding: 12px; border: 1px solid #E5E5E5; font-family: monospace;">${t.name}</td>
                                <td style="padding: 12px; border: 1px solid #E5E5E5;">${t.calls}</td>
                                <td style="padding: 12px; border: 1px solid #E5E5E5;">${(t.success_rate * 100).toFixed(0)}%</td>
                            </tr>
                        `).join('')}
                    </table>

                    <div style="margin-top: 50px; font-size: 11px; color: #7D7D7D; text-align: center; border-top: 1px solid #E5E5E5; padding-top: 20px;">
                        Confidential Security Report · For internal review only
                    </div>
                </div>
            `;

            const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const response = await axios.post(endpoint, {
                html: reportHtml,
                filename: `Sentinel_Analytics_${days}d_${new Date().toISOString().split('T')[0]}.${format}`
            }, { responseType: 'blob' });

            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `Sentinel_Analytics_${days}d.${format}`);
            document.body.appendChild(link);
            link.click();
            link.remove();
        } catch (e: any) {
            console.error("Export failed", e);
            const detail = e.response?.data?.detail || e.message || "Unknown error";
            alert(`Export failed: ${detail}\nPlease check the backend services.`);
        } finally {
            setIsExporting(false);
        }
    };

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const [mcpRes, ingRes, incRes, postRes] = await Promise.all([
                    axios.get(`/api/analytics/mcp-stats?days=${days}`),
                    axios.get(`/api/analytics/ingestion?days=${days}`),
                    axios.get(`/api/analytics/incidents?days=${days}`),
                    axios.get('/api/analytics/posture')
                ]);
                setMcp(mcpRes.data);
                setIngestion(ingRes.data);
                setIncidents(incRes.data);
                setPosture(postRes.data);
            } catch (e) {
                console.error("Failed to fetch analytics", e);
            } finally {
                setTimeout(() => setLoading(false), 300);
            }
        };
        fetchData();
    }, [days]);

    const PageSkeleton = () => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 20 }}>
                {[1, 2, 3, 4].map(i => (
                    <div key={i} className="stat-tile" style={{ borderTop: '3px solid #eee' }}>
                        <div className="skeleton skeleton-text" style={{ width: '60%' }} />
                        <div className="skeleton skeleton-title" style={{ width: '80%', height: 35 }} />
                        <div className="skeleton skeleton-text" style={{ width: '40%' }} />
                    </div>
                ))}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20 }}>
                <div className="card">
                    <div className="skeleton skeleton-title" />
                    <div className="skeleton skeleton-box" style={{ height: 180 }} />
                </div>
                <div className="card">
                    <div className="skeleton skeleton-title" />
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                        {[1, 2, 3].map(i => <div key={i} className="skeleton skeleton-text" style={{ height: 40 }} />)}
                    </div>
                </div>
            </div>
        </div>
    );

    return (
        <div>
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 16 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faChartLine} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Advanced Analytics
                        </div>
                        <div className="page-subtitle">Sentinel operations, ingestion, and MCP intelligence performance</div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                        <div style={{ display: 'flex', gap: 8 }}>
                            <button
                                className="btn btn-secondary btn-sm"
                                onClick={() => handleExport('html')}
                                disabled={isExporting || loading}
                                title="Export HTML"
                            >
                                <FontAwesomeIcon icon={faFileCode} style={{ color: 'var(--info)' }} />
                                HTML
                            </button>
                            <button
                                className="btn btn-primary btn-sm"
                                onClick={() => handleExport('pdf')}
                                disabled={isExporting || loading}
                                title="Export PDF"
                            >
                                <FontAwesomeIcon icon={faFilePdf} />
                                PDF
                            </button>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-card)', padding: '4px 12px', borderRadius: 8, border: '1px solid var(--border-color)', boxShadow: '0 2px 4px rgba(0,0,0,0.02)' }}>
                            <span style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Time Horizon</span>
                            <select
                                value={days}
                                onChange={(e) => setDays(Number(e.target.value))}
                                disabled={loading}
                                style={{
                                    background: 'none',
                                    border: 'none',
                                    color: 'var(--pwc-orange)',
                                    fontSize: 13,
                                    fontWeight: 700,
                                    cursor: 'pointer',
                                    outline: 'none',
                                    padding: '4px 0'
                                }}
                            >
                                <option value={1}>Last 24 Hours</option>
                                <option value={7}>Last 7 Days</option>
                                <option value={30}>Last 30 Days</option>
                                <option value={90}>Last 90 Days</option>
                            </select>
                        </div>

                        <div className="tabs" style={{ display: 'flex', gap: 4, background: 'var(--bg-input)', padding: 4, borderRadius: 8, border: '1px solid var(--border-color)', marginBottom: 0 }}>
                            {(['overview', 'mcp', 'ingestion'] as const).map(t => (
                                <button
                                    key={t}
                                    onClick={() => setTab(t)}
                                    className={`tab ${tab === t ? 'active' : ''}`}
                                    style={{ borderRadius: 6, textTransform: 'capitalize', minWidth: 90 }}
                                >
                                    {t}
                                </button>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            <div className="page-content">
                {loading ? <PageSkeleton /> : (
                    <div className="fade-in">
                        {tab === 'overview' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                                {/* Severity donut */}
                                {incidents && (
                                    <div className="card" style={{ marginBottom: 4 }}>
                                        <div className="chart-title">Incident Severity Distribution</div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 32 }}>
                                            <div style={{ position: 'relative', width: 180, height: 180, flexShrink: 0 }}>
                                                <ResponsiveContainer width="100%" height="100%">
                                                    <PieChart>
                                                        <Pie
                                                            data={[
                                                                { name: 'High',          value: incidents.severity?.high || 0 },
                                                                { name: 'Medium',        value: incidents.severity?.medium || 0 },
                                                                { name: 'Low',           value: incidents.severity?.low || 0 },
                                                                { name: 'Informational', value: incidents.severity?.informational || 0 },
                                                            ]}
                                                            cx="50%" cy="50%"
                                                            innerRadius={55} outerRadius={80}
                                                            dataKey="value" paddingAngle={3}
                                                            startAngle={90} endAngle={-270}
                                                        >
                                                            <Cell fill="#E67E22" />
                                                            <Cell fill="#D4AC0D" />
                                                            <Cell fill="#27AE60" />
                                                            <Cell fill="#2980B9" />
                                                        </Pie>
                                                        <Tooltip contentStyle={{ fontFamily: 'Inter', fontSize: 12, borderRadius: 8 }} />
                                                    </PieChart>
                                                </ResponsiveContainer>
                                                <div style={{
                                                    position: 'absolute', inset: 0,
                                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                    flexDirection: 'column', pointerEvents: 'none',
                                                }}>
                                                    <div className="card-metric-value" style={{ fontSize: 22 }}>
                                                        {(incidents.severity?.high || 0) + (incidents.severity?.medium || 0) +
                                                         (incidents.severity?.low || 0) + (incidents.severity?.informational || 0)}
                                                    </div>
                                                    <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Total</div>
                                                </div>
                                            </div>
                                            <div style={{ flex: 1 }}>
                                                {[
                                                    { label: 'High',          value: incidents.severity?.high || 0,          color: '#E67E22' },
                                                    { label: 'Medium',        value: incidents.severity?.medium || 0,        color: '#D4AC0D' },
                                                    { label: 'Low',           value: incidents.severity?.low || 0,           color: '#27AE60' },
                                                    { label: 'Informational', value: incidents.severity?.informational || 0, color: '#2980B9' },
                                                ].map(s => (
                                                    <div key={s.label} className="kv-row">
                                                        <div className="kv-label" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                            <div style={{ width: 8, height: 8, borderRadius: '50%', background: s.color, flexShrink: 0 }} />
                                                            {s.label}
                                                        </div>
                                                        <div className="kv-value">{s.value}</div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                )}
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 20 }}>
                                    <div className="stat-tile">
                                        <div className="stat-tile-label">Security Posture Score</div>
                                        <div className="stat-tile-value" style={{ color: (posture?.score ?? 0) > 80 ? 'var(--low)' : 'var(--high)' }}>
                                            {posture?.score}/{posture?.max_score}
                                        </div>
                                        <div className="progress-bar-wrap" style={{ marginTop: 10 }}>
                                            <div className={`progress-bar-fill ${(posture?.score ?? 0) > 80 ? 'green' : 'orange'}`}
                                                 style={{ width: `${(posture?.score ?? 0)}%` }} />
                                        </div>
                                    </div>
                                    <div className="stat-tile">
                                        <div className="stat-tile-label">Open Incidents</div>
                                        <div className="stat-tile-value" style={{ color: 'var(--critical)' }}>{incidents?.status.open}</div>
                                        <div className="text-xs text-muted">Active investigations</div>
                                    </div>
                                    <div className="stat-tile">
                                        <div className="stat-tile-label">Data Ingested</div>
                                        <div className="stat-tile-value" style={{ color: 'var(--info)' }}>{ingestion?.total_7d_gb.toFixed(1)} GB</div>
                                        <div className="text-xs text-muted">Total billable ({days}d)</div>
                                    </div>
                                    <div className="stat-tile">
                                        <div className="stat-tile-label">MCP Tool Activity</div>
                                        <div className="stat-tile-value" style={{ color: 'var(--brand)' }}>{mcp?.total_calls}</div>
                                        <div className="text-xs text-muted">Successful calls</div>
                                    </div>
                                </div>

                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20 }}>
                                    <div className="card">
                                        <div className="card-title">
                                            <FontAwesomeIcon icon={faTriangleExclamation} className="card-title-icon" style={{ color: 'var(--critical)' }} />
                                            Sentinel Incidents by Severity
                                        </div>
                                        <div style={{ display: 'flex', gap: 40, padding: '20px 0', alignItems: 'center' }}>
                                            <div style={{ flex: 1 }}>
                                                <SeverityBar label="High" count={incidents?.severity.high ?? 0} color="var(--critical)" max={incidents?.status.closed || 100} />
                                                <SeverityBar label="Medium" count={incidents?.severity.medium ?? 0} color="var(--high)" max={incidents?.status.closed || 100} />
                                                <SeverityBar label="Low" count={incidents?.severity.low ?? 0} color="var(--low)" max={incidents?.status.closed || 100} />
                                                <SeverityBar label="Info" count={incidents?.severity.informational ?? 0} color="var(--info)" max={incidents?.status.closed || 100} />
                                            </div>
                                            <div style={{ textAlign: 'center', minWidth: 140 }}>
                                                <div className="card-metric-value" style={{ fontSize: 36 }}>{incidents?.status.closed}</div>
                                                <div className="text-xs text-muted" style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>Closed ({days}d)</div>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="card">
                                        <div className="card-title">
                                            <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" style={{ color: 'var(--low)' }} />
                                            Improve Posture Score
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                            {posture?.recommendations.map((item, i) => (
                                                <div key={i} style={{ display: 'flex', gap: 12, fontSize: 12, padding: '10px 12px', background: 'var(--pwc-orange-light)', borderRadius: 8, border: '1px solid var(--pwc-orange-border)', alignItems: 'center' }}>
                                                    <div style={{ background: 'var(--brand)', color: 'white', fontWeight: 800, padding: '2px 8px', borderRadius: 10, fontSize: 10 }}>{item.impact}</div>
                                                    <div style={{ flex: 1, color: 'var(--text-primary)', fontWeight: 500 }}>{item.task}</div>
                                                    <span className={`badge ${item.severity === 'High' ? 'badge-critical' : 'badge-high'}`} style={{ fontSize: 10 }}>{item.severity}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {tab === 'mcp' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                                {/* MCP Tool Usage BarChart */}
                                {mcp?.tools && mcp.tools.length > 0 && (
                                    <div className="card" style={{ marginBottom: 0 }}>
                                        <div className="chart-title">MCP Tool Usage</div>
                                        <div className="chart-container chart-container-md">
                                            <ResponsiveContainer width="100%" height="100%">
                                                <BarChart data={mcp.tools.slice(0, 12)} layout="vertical"
                                                          margin={{ top: 0, right: 20, left: 100, bottom: 0 }}>
                                                    <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#F0F0F0" />
                                                    <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                                                    <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} width={100} />
                                                    <Tooltip contentStyle={{ fontFamily: 'Inter', fontSize: 12, borderRadius: 8 }} />
                                                    <Bar dataKey="calls" name="Calls" fill="#D04A02" radius={[0, 4, 4, 0]} />
                                                </BarChart>
                                            </ResponsiveContainer>
                                        </div>
                                    </div>
                                )}
                                {/* Hourly usage AreaChart */}
                                {mcp?.hourly_usage && mcp.hourly_usage.length > 0 && (
                                    <div className="card" style={{ marginBottom: 0 }}>
                                        <div className="chart-title">Hourly Usage Pattern</div>
                                        <div className="chart-container chart-container-sm">
                                            <ResponsiveContainer width="100%" height="100%">
                                                <AreaChart
                                                    data={mcp.hourly_usage.map((v: number, i: number) => ({ hour: `${i}h`, calls: v }))}
                                                    margin={{ top: 4, right: 16, left: -10, bottom: 0 }}
                                                >
                                                    <defs>
                                                        <linearGradient id="gradHourly" x1="0" y1="0" x2="0" y2="1">
                                                            <stop offset="5%" stopColor="#D04A02" stopOpacity={0.2} />
                                                            <stop offset="95%" stopColor="#D04A02" stopOpacity={0} />
                                                        </linearGradient>
                                                    </defs>
                                                    <XAxis dataKey="hour" tick={{ fontSize: 9, fill: 'var(--text-muted)' }} interval={3} />
                                                    <YAxis tick={{ fontSize: 9, fill: 'var(--text-muted)' }} />
                                                    <Tooltip contentStyle={{ fontFamily: 'Inter', fontSize: 12, borderRadius: 8 }} />
                                                    <Area type="monotone" dataKey="calls" stroke="#D04A02" fill="url(#gradHourly)" strokeWidth={2} dot={false} />
                                                </AreaChart>
                                            </ResponsiveContainer>
                                        </div>
                                    </div>
                                )}
                                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 300px', gap: 20 }}>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faToolbox} className="card-title-icon" style={{ color: 'var(--brand)' }} />
                                        MCP Agent Tool Usage Analytics
                                    </div>
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Tool Name</th>
                                                    <th>Total Invocation</th>
                                                    <th>Success Rate</th>
                                                    <th>Performance</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {mcp?.tools.map(t => (
                                                    <tr key={t.name}>
                                                        <td className="mono" style={{ fontWeight: 600 }}>{t.name}</td>
                                                        <td>{t.calls}</td>
                                                        <td>
                                                            <span className={`badge ${t.success_rate > 0.95 ? 'badge-low' : 'badge-high'}`}>
                                                                {(t.success_rate * 100).toFixed(0)}%
                                                            </span>
                                                        </td>
                                                        <td style={{ width: 120 }}>
                                                            <div className="progress-bar-wrap">
                                                                <div className="progress-bar-fill orange"
                                                                     style={{ width: `${t.success_rate * 100}%` }} />
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <div className="card">
                                    <div className="card-title"><FontAwesomeIcon icon={faClock} className="card-title-icon" /> Activity Trend</div>
                                    <div style={{ height: 200, display: 'flex', alignItems: 'flex-end', gap: 4, paddingBottom: 10 }}>
                                        {mcp?.hourly_usage.map((h, i) => (
                                            <div
                                                key={i}
                                                style={{ flex: 1, background: 'var(--brand)', height: `${(h / 400) * 100}%`, borderRadius: '2px 2px 0 0', opacity: 0.6 + (h / 800) }}
                                                title={`Usage: ${h}`}
                                            />
                                        ))}
                                    </div>
                                    <div className="text-xs text-muted" style={{ textAlign: 'center' }}>Relative Frequency ({days}d)</div>
                                </div>
                            </div>
                            </div>
                        )}

                        {tab === 'ingestion' && (
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20 }}>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faDatabase} className="card-title-icon" style={{ color: 'var(--info)' }} />
                                        Workspace Ingestion Details
                                    </div>
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Log Source (Table)</th>
                                                    <th>Invoiced Volume</th>
                                                    <th>Cost Share</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {ingestion?.top_tables.map(t => {
                                                    const total = ingestion.total_7d_gb || 1;
                                                    const percentage = ((t.size_gb / total) * 100).toFixed(1);
                                                    return (
                                                        <tr key={t.table}>
                                                            <td className="mono" style={{ fontWeight: 600 }}>{t.table}</td>
                                                            <td>
                                                                <div className="inline-bar-wrap">
                                                                    <div className="inline-bar">
                                                                        <div className="inline-bar-fill"
                                                                             style={{ width: `${Math.min(100, (t.size_gb / (ingestion?.total_7d_gb || 1)) * 100)}%` }} />
                                                                    </div>
                                                                    <div className="inline-bar-label">{t.size_gb.toFixed(2)} GB</div>
                                                                </div>
                                                            </td>
                                                            <td style={{ width: 220 }}>
                                                                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                                                                    <div className="progress-bar-wrap" style={{ flex: 1 }}>
                                                                        <div className="progress-bar-fill orange"
                                                                             style={{ width: `${percentage}%` }} />
                                                                    </div>
                                                                    <span style={{ minWidth: 45, fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>
                                                                        {percentage}%
                                                                    </span>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    );
                                                })}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                <div className="card">
                                    <div className="card-title"><FontAwesomeIcon icon={faServer} className="card-title-icon" /> Configuration Summary</div>
                                    <div style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 12 }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <span style={{ color: 'var(--text-secondary)' }}>Log Retention</span>
                                            <span style={{ color: 'var(--low)', fontWeight: 600 }}>90 Days</span>
                                        </div>
                                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <span style={{ color: 'var(--text-secondary)' }}>Commitment Tier</span>
                                            <span style={{ fontWeight: 600 }}>Pay-as-you-go</span>
                                        </div>
                                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <span style={{ color: 'var(--text-secondary)' }}>Availability Zone</span>
                                            <span className="mono" style={{ fontSize: 11 }}>East US 2</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}

function SeverityBar({ label, count, color, max }: { label: string; count: number; color: string; max: number }) {
    const width = max > 0 ? (count / max) * 100 : 0;
    return (
        <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                <span>{label}</span>
                <span>{count}</span>
            </div>
            <div style={{ height: 10, background: '#f5f5f5', borderRadius: 5, overflow: 'hidden', border: '1px solid #eee' }}>
                <div style={{ width: `${Math.min(width, 100)}%`, height: '100%', background: color, borderRadius: 5 }} />
            </div>
        </div>
    );
}
