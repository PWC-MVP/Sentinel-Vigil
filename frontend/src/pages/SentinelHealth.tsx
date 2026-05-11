import { useState, useEffect } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faHeartPulse, faDatabase, faServer, faTriangleExclamation,
    faCircleCheck, faCircleXmark, faCircleMinus,
    faChartBar, faFilePdf, faFileCode, faRefresh
} from '@fortawesome/free-solid-svg-icons';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface Overview {
    total_gb: number;
    table_count: number;
    healthy_connectors: number;
    stale_connectors: number;
    critical_connectors: number;
    agents_online: number;
    agents_degraded: number;
    agents_offline: number;
    error?: string;
}
interface Connector {
    table: string;
    last_received: string;
    freshness_hours: number;
    volume_mb: number;
    status: 'Healthy' | 'Stale' | 'Critical' | string;
}
interface Agent {
    name: string;
    os: string;
    last_heartbeat: string;
    stale_minutes: number;
    status: 'Online' | 'Degraded' | 'Offline' | string;
    beat_count: number;
}
interface Gap {
    table: string;
    days_with_data: number;
    gap_days: number;
    total_gb: number;
    avg_daily_gb: number;
}
interface TrendPoint { date: string; gb: number; }

function statusIcon(s: string) {
    if (s === 'Healthy' || s === 'Online')
        return <FontAwesomeIcon icon={faCircleCheck} style={{ color: 'var(--low)', fontSize: 13 }} />;
    if (s === 'Stale' || s === 'Degraded')
        return <FontAwesomeIcon icon={faCircleMinus} style={{ color: 'var(--high)', fontSize: 13 }} />;
    return <FontAwesomeIcon icon={faCircleXmark} style={{ color: 'var(--critical)', fontSize: 13 }} />;
}
function statusBadge(s: string) {
    if (s === 'Healthy' || s === 'Online') return 'badge-low';
    if (s === 'Stale' || s === 'Degraded') return 'badge-high';
    return 'badge-critical';
}
function freshColor(h: number) {
    if (h < 2) return 'var(--low)';
    if (h < 24) return 'var(--high)';
    return 'var(--critical)';
}

export default function SentinelHealth() {
    const [tab, setTab] = useState<'connectors' | 'agents' | 'gaps' | 'trend'>('connectors');
    const [days, setDays] = useState(7);
    const [overview, setOverview] = useState<Overview | null>(null);
    const [connectors, setConnectors] = useState<Connector[]>([]);
    const [agents, setAgents] = useState<Agent[]>([]);
    const [gaps, setGaps] = useState<Gap[]>([]);
    const [trend, setTrend] = useState<TrendPoint[]>([]);
    const [loading, setLoading] = useState(true);
    const [isExporting, setIsExporting] = useState(false);
    const [search, setSearch] = useState('');

    const fetchData = async () => {
        setLoading(true);
        try {
            const [ov, conn, ag, gp, tr] = await Promise.all([
                axios.get(`/api/sentinel-health/overview?days=${days}`),
                axios.get('/api/sentinel-health/connectors'),
                axios.get('/api/sentinel-health/agents'),
                axios.get(`/api/sentinel-health/data-gaps?days=${days}`),
                axios.get(`/api/sentinel-health/ingestion-trend?days=${days}`),
            ]);
            setOverview(ov.data);
            setConnectors(conn.data.connectors || []);
            setAgents(ag.data.agents || []);
            setGaps(gp.data.gaps || []);
            setTrend(tr.data.trend || []);
        } catch (e) {
            console.error('SentinelHealth fetch failed', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, [days]);

    const handleExport = async (format: 'pdf' | 'html') => {
        setIsExporting(true);
        const html = buildExportHtml();
        try {
            const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const res = await axios.post(endpoint, {
                html,
                filename: `Sentinel_Platform_Health_${new Date().toISOString().split('T')[0]}.${format}`
            }, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url;
            a.download = `Sentinel_Platform_Health.${format}`; a.click(); a.remove();
        } catch (e: any) {
            alert(`Export failed: ${e.message}`);
        } finally { setIsExporting(false); }
    };

    const buildExportHtml = () => `
        <div style="font-family:Inter,sans-serif;padding:40px;color:#2D2D2D">
            <h1 style="color:#D04A02;border-bottom:3px solid #D04A02;padding-bottom:16px">
                Sentinel Platform Health Report
            </h1>
            <p style="color:#7D7D7D">Generated: ${new Date().toLocaleString()} · Window: ${days}d</p>
            <h2>Connector Summary</h2>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#F7F7F7"><th style="padding:10px;border:1px solid #E5E5E5;text-align:left">Table</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Status</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Freshness (h)</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Volume MB</th></tr>
                ${connectors.slice(0, 30).map(c => `
                    <tr><td style="padding:8px;border:1px solid #E5E5E5;font-family:monospace">${c.table}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${c.status}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${c.freshness_hours}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${c.volume_mb.toFixed(1)}</td></tr>
                `).join('')}
            </table>
        </div>`;

    const filteredConnectors = connectors.filter(c =>
        c.table.toLowerCase().includes(search.toLowerCase()));
    const maxVolume = Math.max(...connectors.map(c => c.volume_mb), 1);

    const Skeleton = () => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                {[1,2,3,4].map(i => <div key={i} className="stat-tile"><div className="skeleton skeleton-title" /><div className="skeleton skeleton-text" /></div>)}
            </div>
            <div className="card"><div className="skeleton skeleton-box" style={{ height: 200 }} /></div>
        </div>
    );

    return (
        <div>
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faHeartPulse} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Sentinel Platform Health
                        </div>
                        <div className="page-subtitle">Data connector freshness, agent heartbeats, and ingestion gaps</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <button className="btn btn-sm btn-ghost" onClick={() => handleExport('html')} disabled={isExporting || loading}>
                            <FontAwesomeIcon icon={faFileCode} style={{ color: 'var(--info)' }} /> HTML
                        </button>
                        <button className="btn btn-sm btn-ghost" onClick={() => handleExport('pdf')} disabled={isExporting || loading}>
                            <FontAwesomeIcon icon={faFilePdf} style={{ color: 'var(--critical)' }} /> PDF
                        </button>
                        <button className="btn btn-sm btn-ghost" onClick={fetchData} disabled={loading}>
                            <FontAwesomeIcon icon={faRefresh} spin={loading} /> Refresh
                        </button>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-card)', padding: '4px 12px', borderRadius: 8, border: '1px solid var(--border-color)' }}>
                            <span style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Window</span>
                            <select value={days} onChange={e => setDays(Number(e.target.value))} disabled={loading}
                                style={{ background: 'none', border: 'none', color: 'var(--pwc-orange)', fontSize: 13, fontWeight: 700, cursor: 'pointer', outline: 'none', padding: '4px 0' }}>
                                <option value={1}>24 Hours</option>
                                <option value={7}>7 Days</option>
                                <option value={14}>14 Days</option>
                                <option value={30}>30 Days</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <div className="page-content">
                {loading ? <Skeleton /> : (
                    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

                        {/* KPI Row */}
                        <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--low)' }}>
                                <div className="stat-tile-label">Active Tables</div>
                                <div className="stat-tile-value" style={{ color: 'var(--text-primary)' }}>{overview?.table_count ?? 0}</div>
                                <div className="text-muted" style={{ fontSize: 11 }}>{overview?.total_gb.toFixed(1)} GB ingested</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--low)' }}>
                                <div className="stat-tile-label">Healthy Connectors</div>
                                <div className="stat-tile-value" style={{ color: 'var(--low)' }}>{overview?.healthy_connectors ?? 0}</div>
                                <div className="text-muted" style={{ fontSize: 11 }}>Fresh within 2h</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: `3px solid ${(overview?.critical_connectors ?? 0) > 0 ? 'var(--critical)' : 'var(--high)'}` }}>
                                <div className="stat-tile-label">Stale / Critical</div>
                                <div className="stat-tile-value" style={{ color: (overview?.critical_connectors ?? 0) > 0 ? 'var(--critical)' : 'var(--high)' }}>
                                    {(overview?.stale_connectors ?? 0) + (overview?.critical_connectors ?? 0)}
                                </div>
                                <div className="text-muted" style={{ fontSize: 11 }}>{overview?.critical_connectors} critical gaps</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--info)' }}>
                                <div className="stat-tile-label">Connected Agents</div>
                                <div className="stat-tile-value" style={{ color: 'var(--info)' }}>{overview?.agents_online ?? 0}</div>
                                <div className="text-muted" style={{ fontSize: 11 }}>{overview?.agents_degraded} degraded · {overview?.agents_offline} offline</div>
                            </div>
                        </div>

                        {/* Agent status donut + connector health summary cards */}
                        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                            {/* Agent donut */}
                            {overview && (
                                <div className="card-elevated" style={{ flex: '1 1 300px', marginBottom: 0 }}>
                                    <div className="chart-title">Agent Status Distribution</div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
                                        <div style={{ position: 'relative', width: 160, height: 160, flexShrink: 0 }}>
                                            <ResponsiveContainer width="100%" height="100%">
                                                <PieChart>
                                                    <Pie
                                                        data={[
                                                            { name: 'Online',   value: overview.agents_online   || 0 },
                                                            { name: 'Degraded', value: overview.agents_degraded || 0 },
                                                            { name: 'Offline',  value: overview.agents_offline  || 0 },
                                                        ]}
                                                        cx="50%" cy="50%"
                                                        innerRadius={48} outerRadius={70}
                                                        dataKey="value" paddingAngle={4}
                                                        startAngle={90} endAngle={-270}
                                                    >
                                                        <Cell fill="#27AE60" />
                                                        <Cell fill="#D4AC0D" />
                                                        <Cell fill="#C0392B" />
                                                    </Pie>
                                                    <Tooltip contentStyle={{ fontFamily: 'Inter', fontSize: 12, borderRadius: 8 }} />
                                                </PieChart>
                                            </ResponsiveContainer>
                                            <div style={{
                                                position: 'absolute', inset: 0,
                                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                flexDirection: 'column', pointerEvents: 'none',
                                            }}>
                                                <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                                                    {(overview.agents_online || 0) + (overview.agents_degraded || 0) + (overview.agents_offline || 0)}
                                                </div>
                                                <div className="text-muted" style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' }}>Agents</div>
                                            </div>
                                        </div>
                                        <div style={{ flex: 1 }}>
                                            {[
                                                { label: 'Online',   value: overview.agents_online,   color: 'var(--low)',      dot: 'green' },
                                                { label: 'Degraded', value: overview.agents_degraded, color: 'var(--medium)',   dot: 'yellow' },
                                                { label: 'Offline',  value: overview.agents_offline,  color: 'var(--critical)', dot: 'red' },
                                            ].map(r => (
                                                <div key={r.label} className="kv-row">
                                                    <div className="kv-label" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                        <div className={`health-light ${r.dot}`} />
                                                        {r.label}
                                                    </div>
                                                    <div className="kv-value" style={{ color: r.color }}>{r.value ?? 0}</div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            )}
                            {/* Connector health summary cards */}
                            {overview && (
                                <div style={{ flex: '1 1 300px', display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, alignContent: 'start' }}>
                                    {[
                                        { label: 'Healthy',  value: overview.healthy_connectors,  color: 'var(--low)',      dot: 'green' },
                                        { label: 'Stale',    value: overview.stale_connectors,    color: 'var(--medium)',   dot: 'yellow' },
                                        { label: 'Critical', value: overview.critical_connectors, color: 'var(--critical)', dot: 'red' },
                                    ].map(m => (
                                        <div key={m.label} className="card-metric">
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                                                <div className={`health-light ${m.dot}`} />
                                                <div className="card-metric-label">{m.label}</div>
                                            </div>
                                            <div className="card-metric-value" style={{ color: m.color, fontSize: 28 }}>{m.value ?? 0}</div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* Tabs */}
                        <div className="tabs" style={{ marginBottom: 0 }}>
                            {([
                                { id: 'connectors', label: 'Data Connectors', icon: faDatabase },
                                { id: 'agents', label: 'Agent Heartbeats', icon: faServer },
                                { id: 'gaps', label: 'Ingestion Gaps', icon: faTriangleExclamation },
                                { id: 'trend', label: 'Volume Trend', icon: faChartBar },
                            ] as const).map(t => (
                                <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                                    <FontAwesomeIcon icon={t.icon} style={{ marginRight: 8 }} />{t.label}
                                </button>
                            ))}
                        </div>

                        {/* Connectors */}
                        {tab === 'connectors' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, alignItems: 'center' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faDatabase} className="card-title-icon" />
                                        Data Connector Freshness
                                    </div>
                                    <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter tables…"
                                        className="form-input"
                                        style={{ marginLeft: 'auto', width: 200, padding: '6px 12px', height: 34 }} />
                                </div>
                                <div className="data-table-wrap">
                                    <table className="data-table">
                                        <thead>
                                            <tr>
                                                <th>Table / Source</th>
                                                <th style={{ width: 100 }}>Status</th>
                                                <th style={{ width: 130 }}>Freshness</th>
                                                <th>Last Received</th>
                                                <th>Volume Share</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {filteredConnectors.map(c => (
                                                <tr key={c.table}>
                                                    <td>
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                            {statusIcon(c.status)}
                                                            <code style={{ fontSize: 11, fontWeight: 600 }}>{c.table}</code>
                                                        </div>
                                                    </td>
                                                    <td>
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                            <div className={`health-light ${c.status === 'Healthy' ? 'green pulse' : c.status === 'Stale' ? 'yellow' : 'red'}`} />
                                                            <span className={`badge ${statusBadge(c.status)}`}>{c.status}</span>
                                                        </div>
                                                    </td>
                                                    <td style={{ color: freshColor(c.freshness_hours), fontWeight: 700, fontSize: 12 }}>
                                                        {c.freshness_hours < 1
                                                            ? `${Math.round(c.freshness_hours * 60)}m ago`
                                                            : `${c.freshness_hours.toFixed(1)}h ago`}
                                                    </td>
                                                    <td className="text-muted" style={{ fontSize: 11 }}>
                                                        {c.last_received ? new Date(c.last_received).toLocaleString() : '—'}
                                                    </td>
                                                    <td style={{ width: 200 }}>
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                            <div className="progress-bar-wrap" style={{ flex: 1, marginBottom: 0 }}>
                                                                <div className="progress-bar-fill blue"
                                                                     style={{ width: `${Math.min((c.volume_mb / maxVolume) * 100, 100)}%` }} />
                                                            </div>
                                                            <span className="text-muted" style={{ fontSize: 11, minWidth: 55 }}>{c.volume_mb.toFixed(1)} MB</span>
                                                        </div>
                                                    </td>
                                                </tr>
                                            ))}
                                            {filteredConnectors.length === 0 && (
                                                <tr><td colSpan={5} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No connectors found</td></tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}

                        {/* Agents */}
                        {tab === 'agents' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faServer} className="card-title-icon" />
                                        Connected Agent Status ({agents.length} agents)
                                    </div>
                                </div>
                                {agents.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}>
                                        <div className="empty-state-icon"><FontAwesomeIcon icon={faServer} style={{ opacity: 0.3 }} /></div>
                                        <div className="empty-state-text">No Heartbeat data found — the Heartbeat table may not be configured</div>
                                    </div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Computer</th>
                                                    <th style={{ width: 90 }}>OS</th>
                                                    <th style={{ width: 100 }}>Status</th>
                                                    <th style={{ width: 120 }}>Last Heartbeat</th>
                                                    <th style={{ width: 100 }}>Stale For</th>
                                                    <th style={{ width: 80 }}>Beats</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {agents.map(a => (
                                                    <tr key={a.name}>
                                                        <td style={{ fontWeight: 600, fontSize: 12 }}>{a.name}</td>
                                                        <td><span className="badge badge-muted" style={{ fontSize: 10 }}>{a.os || '—'}</span></td>
                                                        <td>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                                {statusIcon(a.status)}
                                                                <span className={`badge ${statusBadge(a.status)}`}>{a.status}</span>
                                                            </div>
                                                        </td>
                                                        <td className="text-muted" style={{ fontSize: 11 }}>
                                                            {a.last_heartbeat ? new Date(a.last_heartbeat).toLocaleString() : '—'}
                                                        </td>
                                                        <td style={{ fontSize: 12, fontWeight: 600, color: a.stale_minutes < 10 ? 'var(--low)' : a.stale_minutes < 60 ? 'var(--high)' : 'var(--critical)' }}>
                                                            {a.stale_minutes < 60 ? `${Math.round(a.stale_minutes)}m` : `${(a.stale_minutes / 60).toFixed(1)}h`}
                                                        </td>
                                                        <td className="text-muted" style={{ fontSize: 12 }}>{a.beat_count.toLocaleString()}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Data Gaps */}
                        {tab === 'gaps' && (
                            <div>
                            {/* Gap warning cards */}
                            {gaps.filter(g => g.gap_days > 0).length > 0 && (
                                <div style={{ marginBottom: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
                                    {gaps.filter(g => g.gap_days > 0).map((gap) => (
                                        <div key={gap.table} className="card-elevated" style={{
                                            borderLeft: '3px solid var(--critical)',
                                            padding: '12px 16px',
                                            marginBottom: 0,
                                            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                        }}>
                                            <div>
                                                <div className="mono" style={{ fontSize: 12, fontWeight: 600 }}>{gap.table}</div>
                                                <div className="text-muted" style={{ fontSize: 11, marginTop: 2 }}>
                                                    {gap.days_with_data} days with data · {gap.total_gb?.toFixed(2)} GB total
                                                </div>
                                            </div>
                                            <div style={{ textAlign: 'right' }}>
                                                <div className="card-metric-value" style={{ fontSize: 24, color: 'var(--critical)' }}>{gap.gap_days}</div>
                                                <div style={{ fontSize: 10, color: 'var(--critical)', fontWeight: 600, textTransform: 'uppercase' }}>Gap Days</div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 12 }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faTriangleExclamation} className="card-title-icon" style={{ color: 'var(--high)' }} />
                                        Ingestion Gaps ({days}-day window)
                                    </div>
                                    <div className="text-muted" style={{ marginLeft: 'auto', fontSize: 12 }}>
                                        Tables with missing days of data
                                    </div>
                                </div>
                                {gaps.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}>
                                        <div className="empty-state-icon"><FontAwesomeIcon icon={faCircleCheck} style={{ color: 'var(--low)', opacity: 0.6 }} /></div>
                                        <div className="empty-state-text">No gaps detected — all tables received data every day</div>
                                    </div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Table</th>
                                                    <th style={{ width: 110 }}>Days w/ Data</th>
                                                    <th style={{ width: 90 }}>Gap Days</th>
                                                    <th style={{ width: 100 }}>Total GB</th>
                                                    <th>Coverage</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {gaps.map(g => {
                                                    const pct = Math.round((g.days_with_data / days) * 100);
                                                    return (
                                                        <tr key={g.table}>
                                                            <td><code style={{ fontSize: 11, fontWeight: 600 }}>{g.table}</code></td>
                                                            <td style={{ fontWeight: 700 }}>{g.days_with_data} / {days}</td>
                                                            <td>
                                                                <span className={`badge ${g.gap_days >= 3 ? 'badge-critical' : 'badge-high'}`}>
                                                                    {g.gap_days}d gap
                                                                </span>
                                                            </td>
                                                            <td style={{ fontSize: 12 }}>{g.total_gb.toFixed(3)}</td>
                                                            <td style={{ width: 200 }}>
                                                                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                                                    <div className="progress-bar-wrap" style={{ flex: 1, marginBottom: 0 }}>
                                                                        <div className={`progress-bar-fill ${pct < 50 ? 'red' : pct < 80 ? 'orange' : 'green'}`}
                                                                             style={{ width: `${pct}%` }} />
                                                                    </div>
                                                                    <span className="text-muted" style={{ fontSize: 11, minWidth: 32 }}>{pct}%</span>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    );
                                                })}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                            </div>
                        )}

                        {/* Ingestion Trend */}
                        {tab === 'trend' && (
                            <div className="card">
                                <div className="card-title">
                                    <FontAwesomeIcon icon={faChartBar} className="card-title-icon" style={{ color: 'var(--info)' }} />
                                    Daily Ingestion Volume ({days}-day trend)
                                </div>
                                {trend.length === 0 ? (
                                    <div className="empty-state"><div className="empty-state-text">No trend data available</div></div>
                                ) : (
                                    <div>
                                        {/* Recharts LineChart */}
                                        <div className="chart-container chart-container-md" style={{ marginBottom: 16 }}>
                                            <ResponsiveContainer width="100%" height="100%">
                                                <LineChart data={trend} margin={{ top: 4, right: 16, left: -10, bottom: 0 }}>
                                                    <defs>
                                                        <linearGradient id="gradHealth" x1="0" y1="0" x2="0" y2="1">
                                                            <stop offset="5%" stopColor="#D04A02" stopOpacity={0.1} />
                                                            <stop offset="95%" stopColor="#D04A02" stopOpacity={0} />
                                                        </linearGradient>
                                                    </defs>
                                                    <CartesianGrid strokeDasharray="3 3" stroke="#F0F0F0" vertical={false} />
                                                    <XAxis dataKey="date" tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                                                           tickFormatter={(d: string) => d.slice(5)} />
                                                    <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                                                           tickFormatter={(v: number) => `${v.toFixed(1)}GB`} />
                                                    <Tooltip formatter={(v: any) => [`${Number(v).toFixed(2)} GB`, 'Volume']}
                                                             contentStyle={{ fontFamily: 'Inter', fontSize: 12, borderRadius: 8 }} />
                                                    <Line type="monotone" dataKey="gb" stroke="#D04A02" strokeWidth={2} dot={false} />
                                                </LineChart>
                                            </ResponsiveContainer>
                                        </div>
                                        <div className="data-table-wrap" style={{ marginTop: 16 }}>
                                            <table className="data-table">
                                                <thead><tr><th>Date</th><th>Volume (GB)</th><th>vs Avg</th></tr></thead>
                                                <tbody>
                                                    {(() => {
                                                        const avg = trend.reduce((s, t) => s + t.gb, 0) / (trend.length || 1);
                                                        return trend.slice().reverse().map(t => {
                                                            const delta = avg > 0 ? ((t.gb - avg) / avg) * 100 : 0;
                                                            return (
                                                                <tr key={t.date}>
                                                                    <td style={{ fontSize: 12 }}>{t.date}</td>
                                                                    <td style={{ fontWeight: 700 }}>{t.gb.toFixed(2)} GB</td>
                                                                    <td>
                                                                        <span className={`badge ${delta > 20 ? 'badge-critical' : delta < -20 ? 'badge-info' : 'badge-muted'}`} style={{ fontSize: 11, fontWeight: 600 }}>
                                                                            {delta > 0 ? '+' : ''}{delta.toFixed(1)}%
                                                                        </span>
                                                                    </td>
                                                                </tr>
                                                            );
                                                        });
                                                    })()}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
