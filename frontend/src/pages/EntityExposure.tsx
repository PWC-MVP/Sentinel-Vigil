import { useState, useEffect } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faUserShield, faUser, faBrain, faServer, faCircleNodes,
    faFilePdf, faFileCode, faRefresh
} from '@fortawesome/free-solid-svg-icons';

interface Overview { risky_users: number; anomalous_users: number; risky_hosts: number; alert_entities: number; }
interface RiskyUser { upn: string; risk_level: string; risk_state: string; department: string; job_title: string; is_admin: boolean; risky_signins?: number; }
interface Anomaly { user: string; device: string; anomaly_count: number; last_anomaly: string; activity_types: string[]; }
interface AlertEntity { type: string; name: string; alert_count: number; severities: string[]; alert_types: string[]; last_seen: string; }
interface RiskyHost { name: string; event_count: number; event_types: string[]; last_seen: string; unique_accounts: number; }

function riskBadge(level: string) {
    const l = (level || '').toLowerCase();
    if (l === 'high') return 'badge-critical';
    if (l === 'medium') return 'badge-high';
    if (l === 'low') return 'badge-low';
    return 'badge-muted';
}
export default function EntityExposure() {
    const [tab, setTab] = useState<'riskyusers' | 'behavior' | 'entities' | 'hosts'>('riskyusers');
    const [days, setDays] = useState(7);
    const [overview, setOverview] = useState<Overview | null>(null);
    const [riskyUsers, setRiskyUsers] = useState<{ source: string; users: RiskyUser[] }>({ source: '', users: [] });
    const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
    const [entities, setEntities] = useState<AlertEntity[]>([]);
    const [hosts, setHosts] = useState<RiskyHost[]>([]);
    const [loading, setLoading] = useState(true);
    const [isExporting, setIsExporting] = useState(false);
    const [entityFilter, setEntityFilter] = useState('All');

    const fetchData = async () => {
        setLoading(true);
        try {
            const [ov, ru, an, en, ho] = await Promise.all([
                axios.get(`/api/entity-exposure/overview?days=${days}`),
                axios.get(`/api/entity-exposure/risky-users?days=${days}`),
                axios.get(`/api/entity-exposure/anomalous-behavior?days=${days}`),
                axios.get(`/api/entity-exposure/alert-entities?days=${days}`),
                axios.get(`/api/entity-exposure/risky-hosts?days=${days}`),
            ]);
            setOverview(ov.data);
            setRiskyUsers(ru.data);
            setAnomalies(an.data.anomalies || []);
            setEntities(en.data.entities || []);
            setHosts(ho.data.hosts || []);
        } catch (e) {
            console.error('EntityExposure fetch failed', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, [days]);

    const filteredEntities = entityFilter === 'All'
        ? entities
        : entities.filter(e => e.type === entityFilter);
    const entityTypes = ['All', ...Array.from(new Set(entities.map(e => e.type)))];
    const maxEntityAlerts = Math.max(...filteredEntities.map(e => e.alert_count), 1);
    const maxHostEvents = Math.max(...hosts.map(h => h.event_count), 1);

    const handleExport = async (format: 'pdf' | 'html') => {
        setIsExporting(true);
        const html = `<div style="font-family:Inter,sans-serif;padding:40px;color:#2D2D2D">
            <h1 style="color:#D04A02;border-bottom:3px solid #D04A02;padding-bottom:16px">Entity Exposure Report</h1>
            <p>Period: Last ${days} days · Generated: ${new Date().toLocaleString()}</p>
            <h2>Risky Users (${riskyUsers.users.length})</h2>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#F7F7F7"><th style="padding:10px;border:1px solid #E5E5E5;text-align:left">UPN</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Risk Level</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Department</th></tr>
                ${riskyUsers.users.slice(0,20).map(u => `<tr>
                    <td style="padding:8px;border:1px solid #E5E5E5;font-family:monospace">${u.upn}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${u.risk_level}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${u.department || '—'}</td>
                </tr>`).join('')}
            </table></div>`;
        try {
            const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const res = await axios.post(endpoint, { html, filename: `Entity_Exposure_${days}d.${format}` }, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url; a.download = `Entity_Exposure.${format}`; a.click(); a.remove();
        } catch (e: any) { alert(`Export failed: ${e.message}`); }
        finally { setIsExporting(false); }
    };

    const Skeleton = () => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                {[1,2,3,4].map(i => <div key={i} className="stat-tile"><div className="skeleton skeleton-title" /><div className="skeleton skeleton-text" /></div>)}
            </div>
            <div className="card"><div className="skeleton skeleton-box" style={{ height: 260 }} /></div>
        </div>
    );

    return (
        <div>
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faUserShield} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Entity Exposure
                        </div>
                        <div className="page-subtitle">Risky identities, behavioral anomalies, and high-alert entities from Sentinel telemetry</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <button className="btn btn-secondary btn-sm" onClick={() => handleExport('html')} disabled={isExporting || loading}>
                            <FontAwesomeIcon icon={faFileCode} style={{ color: 'var(--info)' }} /> HTML
                        </button>
                        <button className="btn btn-primary btn-sm" onClick={() => handleExport('pdf')} disabled={isExporting || loading}>
                            <FontAwesomeIcon icon={faFilePdf} /> PDF
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
                                <option value={30}>30 Days</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <div className="page-content">
                {loading ? <Skeleton /> : (
                    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                        {/* KPIs */}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 16, marginBottom: 4 }}>
                            {[
                                { label: 'Risky Users',      value: overview?.risky_users,     color: '#C0392B', varColor: 'var(--critical)', tab: 'riskyusers' as const },
                                { label: 'Anomalous Users',  value: overview?.anomalous_users,  color: '#E67E22', varColor: 'var(--high)',     tab: 'behavior'   as const },
                                { label: 'Risky Hosts',      value: overview?.risky_hosts,      color: '#D4AC0D', varColor: 'var(--medium)',   tab: 'hosts'      as const },
                                { label: 'Alert Entities',   value: overview?.alert_entities,   color: '#2980B9', varColor: 'var(--info)',     tab: 'entities'   as const },
                            ].map(m => (
                                <div
                                    key={m.label}
                                    className="card-metric"
                                    style={{ '--card-top-color': m.color, cursor: 'pointer' } as React.CSSProperties}
                                    onClick={() => setTab(m.tab)}
                                >
                                    <div className="card-metric-value" style={{ color: m.varColor, fontSize: 28 }}>
                                        {m.value ?? '—'}
                                    </div>
                                    <div className="card-metric-label">{m.label}</div>
                                </div>
                            ))}
                        </div>

                        {/* Tabs */}
                        <div className="tabs" style={{ marginBottom: 0 }}>
                            {([
                                { id: 'riskyusers', label: 'Risky Users', icon: faUser },
                                { id: 'behavior', label: 'Behavioral Anomalies', icon: faBrain },
                                { id: 'entities', label: 'Alert Entities', icon: faCircleNodes },
                                { id: 'hosts', label: 'Risky Hosts', icon: faServer },
                            ] as const).map(t => (
                                <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                                    <FontAwesomeIcon icon={t.icon} style={{ marginRight: 8 }} />{t.label}
                                </button>
                            ))}
                        </div>

                        {/* Risky Users */}
                        {tab === 'riskyusers' && (
                            <div className="card card-elevated" style={{ padding: 0 }}>
                                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 10, alignItems: 'center' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faUser} className="card-title-icon" style={{ color: 'var(--critical)' }} />
                                        Risky Users ({riskyUsers.users.length})
                                    </div>
                                    {riskyUsers.source && (
                                        <span className="badge badge-muted" style={{ marginLeft: 'auto', fontSize: 10 }}>Source: {riskyUsers.source}</span>
                                    )}
                                </div>
                                {riskyUsers.users.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}>
                                        <div className="empty-state-icon"><FontAwesomeIcon icon={faUser} style={{ opacity: 0.3 }} /></div>
                                        <div className="empty-state-text">No risky users found — IdentityInfo or SigninLogs may not be available</div>
                                    </div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th style={{ width: 36 }}></th>
                                                    <th>User Principal Name</th>
                                                    <th style={{ width: 100 }}>Risk Level</th>
                                                    <th>Department</th>
                                                    <th>Job Title</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {riskyUsers.users.map((u, i) => (
                                                    <tr key={i}>
                                                        <td style={{ width: 36, paddingRight: 0 }}>
                                                            <div className="avatar avatar-sm avatar-orange">
                                                                {(u.upn || '??').slice(0, 2).toUpperCase()}
                                                            </div>
                                                        </td>
                                                        <td>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 600, fontSize: 12 }}>
                                                                {u.upn}
                                                                {u.is_admin && (
                                                                    <span style={{ color: 'var(--pwc-orange)', fontSize: 11 }} title="Admin">🛡</span>
                                                                )}
                                                            </div>
                                                        </td>
                                                        <td>
                                                            <span className={`badge ${riskBadge(u.risk_level)}`}>{u.risk_level || 'Unknown'}</span>
                                                        </td>
                                                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{u.department || '—'}</td>
                                                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{u.job_title || '—'}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Behavioral Anomalies */}
                        {tab === 'behavior' && (
                            <div className="card card-elevated" style={{ padding: 0 }}>
                                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faBrain} className="card-title-icon" style={{ color: 'var(--high)' }} />
                                        Behavioral Anomalies from BehaviorAnalytics
                                    </div>
                                </div>
                                {anomalies.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}>
                                        <div className="empty-state-icon"><FontAwesomeIcon icon={faBrain} style={{ opacity: 0.3 }} /></div>
                                        <div className="empty-state-text">No behavioral anomalies — BehaviorAnalytics may not be enabled</div>
                                    </div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>User</th>
                                                    <th style={{ width: 180 }}>Device</th>
                                                    <th style={{ width: 110 }}>Anomalies</th>
                                                    <th style={{ width: 140 }}>Last Anomaly</th>
                                                    <th>Activity Types</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {anomalies.map((a, i) => (
                                                    <tr key={i}>
                                                        <td style={{ fontWeight: 600, fontSize: 12 }}>{a.user}</td>
                                                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a.device || '—'}</td>
                                                        <td>
                                                            <span className={`badge ${a.anomaly_count > 10 ? 'badge-critical' : a.anomaly_count > 3 ? 'badge-high' : 'badge-medium'}`}>
                                                                {a.anomaly_count}
                                                            </span>
                                                        </td>
                                                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                            {a.last_anomaly ? new Date(a.last_anomaly).toLocaleDateString() : '—'}
                                                        </td>
                                                        <td>
                                                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                                                                {(Array.isArray(a.activity_types) ? a.activity_types : []).slice(0, 4).map((t, j) => (
                                                                    <span key={j} className="chip" style={{ fontSize: 10, padding: '2px 8px', cursor: 'default' }}>{t}</span>
                                                                ))}
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Alert Entities */}
                        {tab === 'entities' && (
                            <div className="card card-elevated" style={{ padding: 0 }}>
                                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faCircleNodes} className="card-title-icon" />
                                        Top Entities from Security Alerts
                                    </div>
                                    <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                                        {entityTypes.map(t => (
                                            <button key={t} onClick={() => setEntityFilter(t)}
                                                className={`btn btn-sm ${entityFilter === t ? 'btn-primary' : 'btn-ghost'}`}
                                                style={{ borderRadius: 6, fontSize: 11, padding: '4px 10px', textTransform: 'capitalize' }}>
                                                {t}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                                {filteredEntities.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}><div className="empty-state-text">No entity data available</div></div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th style={{ width: 120 }}>Type</th>
                                                    <th>Entity Name</th>
                                                    <th style={{ width: 90 }}>Alerts</th>
                                                    <th>Volume</th>
                                                    <th>Severities</th>
                                                    <th style={{ width: 130 }}>Last Seen</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {filteredEntities.map((e, i) => (
                                                    <tr key={i}>
                                                        <td>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                                <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                                                                    {e.type?.toLowerCase().includes('account') || e.type?.toLowerCase().includes('user') ? '👤'
                                                                     : e.type?.toLowerCase().includes('host') || e.type?.toLowerCase().includes('device') ? '🖥'
                                                                     : e.type?.toLowerCase().includes('ip') ? '🌐'
                                                                     : '⚠️'}
                                                                </span>
                                                                <span style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{e.type}</span>
                                                            </div>
                                                        </td>
                                                        <td style={{ fontWeight: 600, fontSize: 12, fontFamily: 'monospace' }}>{e.name}</td>
                                                        <td style={{ fontWeight: 700, color: 'var(--brand)' }}>{e.alert_count.toLocaleString()}</td>
                                                        <td style={{ width: 150 }}>
                                                            <div className="progress-bar-wrap">
                                                                <div className="progress-bar-fill orange"
                                                                     style={{ width: `${(e.alert_count / maxEntityAlerts) * 100}%` }} />
                                                            </div>
                                                        </td>
                                                        <td>
                                                            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                                                                {(Array.isArray(e.severities) ? e.severities : []).map((s, j) => (
                                                                    <span key={j} className={`badge ${s === 'High' ? 'badge-critical' : s === 'Medium' ? 'badge-high' : 'badge-low'}`} style={{ fontSize: 9 }}>{s}</span>
                                                                ))}
                                                            </div>
                                                        </td>
                                                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                            {e.last_seen ? new Date(e.last_seen).toLocaleDateString() : '—'}
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Risky Hosts */}
                        {tab === 'hosts' && (
                            <div className="card card-elevated" style={{ padding: 0 }}>
                                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faServer} className="card-title-icon" style={{ color: 'var(--info)' }} />
                                        Hosts with Suspicious Security Events
                                    </div>
                                </div>
                                {hosts.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}>
                                        <div className="empty-state-icon"><FontAwesomeIcon icon={faServer} style={{ opacity: 0.3 }} /></div>
                                        <div className="empty-state-text">No risky hosts — SecurityEvent table may not be ingested</div>
                                    </div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Computer Name</th>
                                                    <th style={{ width: 100 }}>Events</th>
                                                    <th style={{ width: 110 }}>Accounts</th>
                                                    <th>Event Types</th>
                                                    <th>Volume</th>
                                                    <th style={{ width: 130 }}>Last Seen</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {hosts.map((h, i) => (
                                                    <tr key={i}>
                                                        <td style={{ fontWeight: 600, fontSize: 12 }}>{h.name}</td>
                                                        <td style={{ fontWeight: 700, color: h.event_count > 100 ? 'var(--critical)' : 'var(--text-primary)' }}>
                                                            {h.event_count.toLocaleString()}
                                                        </td>
                                                        <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{h.unique_accounts}</td>
                                                        <td>
                                                            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                                                                {(Array.isArray(h.event_types) ? h.event_types : []).slice(0, 5).map((t, j) => (
                                                                    <span key={j} className="badge badge-muted" style={{ fontSize: 10 }}>EventID {t}</span>
                                                                ))}
                                                            </div>
                                                        </td>
                                                        <td style={{ width: 150 }}>
                                                            <div className="progress-bar-wrap">
                                                                <div className="progress-bar-fill orange"
                                                                     style={{ width: `${(h.event_count / maxHostEvents) * 100}%` }} />
                                                            </div>
                                                        </td>
                                                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                            {h.last_seen ? new Date(h.last_seen).toLocaleDateString() : '—'}
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
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
