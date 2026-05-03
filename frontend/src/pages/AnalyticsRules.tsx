import { useState, useEffect, useMemo } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faListCheck, faChartBar, faShieldHalved, faTriangleExclamation,
    faSearch, faBellSlash, faFilePdf, faFileCode, faRefresh
} from '@fortawesome/free-solid-svg-icons';

interface Overview { total_alerts: number; unique_rules: number; high_alerts: number; medium_alerts: number; low_alerts: number; }
interface Rule { name: string; product: string; severity: string; alert_count: number; last_fired: string; first_fired: string; linked_incidents: number; }
interface TacticRow { tactic: string; alert_count: number; unique_rules: number; }
interface TrendPoint { date: string; High: number; Medium: number; Low: number; Informational: number; }
interface SilentRule { name: string; product: string; severity: string; last_fired: string; total_alerts: number; }

function sevColor(s: string) {
    if (s === 'High') return 'var(--critical)';
    if (s === 'Medium') return 'var(--high)';
    if (s === 'Low') return 'var(--low)';
    return 'var(--info)';
}
function sevBadge(s: string) {
    if (s === 'High') return 'badge-critical';
    if (s === 'Medium') return 'badge-high';
    if (s === 'Low') return 'badge-low';
    return 'badge-muted';
}

export default function AnalyticsRules() {
    const [tab, setTab] = useState<'activity' | 'tactic' | 'trend' | 'silent'>('activity');
    const [days, setDays] = useState(30);
    const [overview, setOverview] = useState<Overview | null>(null);
    const [rules, setRules] = useState<Rule[]>([]);
    const [tactics, setTactics] = useState<TacticRow[]>([]);
    const [trend, setTrend] = useState<TrendPoint[]>([]);
    const [silentRules, setSilentRules] = useState<SilentRule[]>([]);
    const [loading, setLoading] = useState(true);
    const [isExporting, setIsExporting] = useState(false);
    const [search, setSearch] = useState('');
    const [sevFilter, setSevFilter] = useState('All');

    const fetchData = async () => {
        setLoading(true);
        try {
            const [ov, act, tac, tr, sr] = await Promise.all([
                axios.get(`/api/analytics-rules/overview?days=${days}`),
                axios.get(`/api/analytics-rules/activity?days=${days}`),
                axios.get(`/api/analytics-rules/by-tactic?days=${days}`),
                axios.get(`/api/analytics-rules/trend?days=${days}`),
                axios.get(`/api/analytics-rules/silent-rules?days=${days}`),
            ]);
            setOverview(ov.data);
            setRules(act.data.rules || []);
            setTactics(tac.data.tactics || []);
            setTrend(tr.data.trend || []);
            setSilentRules(sr.data.silent_rules || []);
        } catch (e) {
            console.error('AnalyticsRules fetch failed', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, [days]);

    const filteredRules = useMemo(() =>
        rules.filter(r =>
            (sevFilter === 'All' || r.severity === sevFilter) &&
            r.name.toLowerCase().includes(search.toLowerCase())
        ), [rules, search, sevFilter]);

    const maxAlerts = Math.max(...filteredRules.map(r => r.alert_count), 1);
    const maxTacticAlerts = Math.max(...tactics.map(t => t.alert_count), 1);
    const maxTrend = Math.max(...trend.map(t => t.High + t.Medium + t.Low + t.Informational), 1);

    const handleExport = async (format: 'pdf' | 'html') => {
        setIsExporting(true);
        const html = `<div style="font-family:Inter,sans-serif;padding:40px;color:#2D2D2D">
            <h1 style="color:#D04A02;border-bottom:3px solid #D04A02;padding-bottom:16px">Analytics Rules Report</h1>
            <p>Period: Last ${days} days · Generated: ${new Date().toLocaleString()}</p>
            <p><strong>Total Alerts:</strong> ${overview?.total_alerts} · <strong>Active Rules:</strong> ${overview?.unique_rules}</p>
            <h2>Top Firing Rules</h2>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#F7F7F7"><th style="padding:10px;border:1px solid #E5E5E5;text-align:left">Rule</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Severity</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Alerts</th></tr>
                ${rules.slice(0,20).map(r => `<tr>
                    <td style="padding:8px;border:1px solid #E5E5E5">${r.name}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${r.severity}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;font-weight:700">${r.alert_count}</td>
                </tr>`).join('')}
            </table></div>`;
        try {
            const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const res = await axios.post(endpoint, { html, filename: `Analytics_Rules_${days}d.${format}` }, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url; a.download = `Analytics_Rules.${format}`; a.click(); a.remove();
        } catch (e: any) { alert(`Export failed: ${e.message}`); }
        finally { setIsExporting(false); }
    };

    const Skeleton = () => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                {[1,2,3,4].map(i => <div key={i} className="stat-tile"><div className="skeleton skeleton-title" /><div className="skeleton skeleton-text" /></div>)}
            </div>
            <div className="card"><div className="skeleton skeleton-box" style={{ height: 280 }} /></div>
        </div>
    );

    return (
        <div>
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faListCheck} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Analytics Rules
                        </div>
                        <div className="page-subtitle">Detection rule coverage, alert volume, MITRE tactic distribution, and silent rules</div>
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
                            <span style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Period</span>
                            <select value={days} onChange={e => setDays(Number(e.target.value))} disabled={loading}
                                style={{ background: 'none', border: 'none', color: 'var(--pwc-orange)', fontSize: 13, fontWeight: 700, cursor: 'pointer', outline: 'none', padding: '4px 0' }}>
                                <option value={7}>7 Days</option>
                                <option value={30}>30 Days</option>
                                <option value={90}>90 Days</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <div className="page-content">
                {loading ? <Skeleton /> : (
                    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                        {/* KPIs */}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--brand)' }}>
                                <div className="stat-tile-label">Active Rules</div>
                                <div className="stat-tile-value">{overview?.unique_rules ?? 0}</div>
                                <div className="text-xs text-muted">Fired at least once</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--info)' }}>
                                <div className="stat-tile-label">Total Alerts</div>
                                <div className="stat-tile-value" style={{ color: 'var(--info)' }}>{(overview?.total_alerts ?? 0).toLocaleString()}</div>
                                <div className="text-xs text-muted">Last {days} days</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--critical)' }}>
                                <div className="stat-tile-label">High Severity</div>
                                <div className="stat-tile-value" style={{ color: 'var(--critical)' }}>{(overview?.high_alerts ?? 0).toLocaleString()}</div>
                                <div className="text-xs text-muted">Immediate action required</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: `3px solid ${silentRules.length > 0 ? 'var(--high)' : 'var(--low)'}` }}>
                                <div className="stat-tile-label">Silent Rules</div>
                                <div className="stat-tile-value" style={{ color: silentRules.length > 0 ? 'var(--high)' : 'var(--low)' }}>{silentRules.length}</div>
                                <div className="text-xs text-muted">Not fired in {days}d</div>
                            </div>
                        </div>

                        {/* Tabs */}
                        <div className="tabs" style={{ marginBottom: 0 }}>
                            {([
                                { id: 'activity', label: 'Rule Activity', icon: faListCheck },
                                { id: 'tactic', label: 'MITRE Tactics', icon: faShieldHalved },
                                { id: 'trend', label: 'Alert Trend', icon: faChartBar },
                                { id: 'silent', label: 'Silent Rules', icon: faBellSlash },
                            ] as const).map(t => (
                                <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                                    <FontAwesomeIcon icon={t.icon} style={{ marginRight: 8 }} />{t.label}
                                    {t.id === 'silent' && silentRules.length > 0 && (
                                        <span className="badge badge-high" style={{ marginLeft: 6, padding: '1px 6px', fontSize: 10 }}>{silentRules.length}</span>
                                    )}
                                </button>
                            ))}
                        </div>

                        {/* Rule Activity */}
                        {tab === 'activity' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                                    <div style={{ position: 'relative', flex: 1, minWidth: 180 }}>
                                        <FontAwesomeIcon icon={faSearch} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 12 }} />
                                        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search rules…"
                                            style={{ width: '100%', paddingLeft: 30, paddingRight: 10, padding: '7px 10px 7px 28px', border: '1px solid var(--border-color)', borderRadius: 6, fontSize: 12, background: 'var(--bg-input)', color: 'var(--text-primary)', boxSizing: 'border-box' }} />
                                    </div>
                                    <div style={{ display: 'flex', gap: 6 }}>
                                        {(['All', 'High', 'Medium', 'Low', 'Informational'] as const).map(s => (
                                            <button key={s} onClick={() => setSevFilter(s)}
                                                className={`btn btn-sm ${sevFilter === s ? 'btn-primary' : 'btn-ghost'}`}
                                                style={{ borderRadius: 6, fontSize: 11, padding: '4px 10px' }}>
                                                {s}
                                            </button>
                                        ))}
                                    </div>
                                    <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 'auto' }}>{filteredRules.length} rules</span>
                                </div>
                                <div className="data-table-wrap">
                                    <table className="data-table">
                                        <thead>
                                            <tr>
                                                <th>Rule Name</th>
                                                <th style={{ width: 90 }}>Severity</th>
                                                <th style={{ width: 90 }}>Alerts</th>
                                                <th style={{ width: 90 }}>Incidents</th>
                                                <th>Volume</th>
                                                <th style={{ width: 130 }}>Last Fired</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {filteredRules.map((r, i) => (
                                                <tr key={i}>
                                                    <td style={{ fontWeight: 600, fontSize: 12 }}>{r.name}</td>
                                                    <td><span className={`badge ${sevBadge(r.severity)}`}>{r.severity}</span></td>
                                                    <td style={{ fontWeight: 700, color: sevColor(r.severity) }}>{r.alert_count.toLocaleString()}</td>
                                                    <td style={{ color: 'var(--text-muted)' }}>{r.linked_incidents.toLocaleString()}</td>
                                                    <td style={{ width: 160 }}>
                                                        <div style={{ height: 8, background: '#f0f0f0', borderRadius: 4 }}>
                                                            <div style={{ width: `${(r.alert_count / maxAlerts) * 100}%`, height: '100%', background: sevColor(r.severity), borderRadius: 4, opacity: 0.85 }} />
                                                        </div>
                                                    </td>
                                                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                        {r.last_fired ? new Date(r.last_fired).toLocaleDateString() : '—'}
                                                    </td>
                                                </tr>
                                            ))}
                                            {filteredRules.length === 0 && (
                                                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No rules match the filter</td></tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}

                        {/* MITRE Tactics */}
                        {tab === 'tactic' && (
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20 }}>
                                <div className="card" style={{ padding: 0 }}>
                                    <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
                                        <div className="card-title" style={{ margin: 0 }}>
                                            <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" />
                                            Alerts by MITRE ATT&amp;CK Tactic
                                        </div>
                                    </div>
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead><tr><th>Tactic</th><th style={{ width: 90 }}>Alerts</th><th style={{ width: 90 }}>Rules</th><th>Volume</th></tr></thead>
                                            <tbody>
                                                {tactics.map(t => (
                                                    <tr key={t.tactic}>
                                                        <td style={{ fontWeight: 600, fontSize: 12 }}>{t.tactic}</td>
                                                        <td style={{ fontWeight: 700 }}>{t.alert_count.toLocaleString()}</td>
                                                        <td style={{ color: 'var(--text-muted)' }}>{t.unique_rules}</td>
                                                        <td style={{ width: 180 }}>
                                                            <div style={{ height: 10, background: '#f0f0f0', borderRadius: 5 }}>
                                                                <div style={{ width: `${(t.alert_count / maxTacticAlerts) * 100}%`, height: '100%', background: 'linear-gradient(90deg, var(--brand) 0%, #ff8c42 100%)', borderRadius: 5 }} />
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                                {tactics.length === 0 && <tr><td colSpan={4} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No tactic data — alerts may not have Tactics populated</td></tr>}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faTriangleExclamation} className="card-title-icon" style={{ color: 'var(--high)' }} />
                                        Severity Distribution
                                    </div>
                                    {[
                                        { label: 'High', count: overview?.high_alerts ?? 0, color: 'var(--critical)' },
                                        { label: 'Medium', count: overview?.medium_alerts ?? 0, color: 'var(--high)' },
                                        { label: 'Low', count: overview?.low_alerts ?? 0, color: 'var(--low)' },
                                    ].map(s => {
                                        const pct = (overview?.total_alerts ?? 0) > 0 ? (s.count / (overview?.total_alerts ?? 1)) * 100 : 0;
                                        return (
                                            <div key={s.label} style={{ marginBottom: 16 }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
                                                    <span style={{ fontWeight: 700, color: s.color, textTransform: 'uppercase' }}>{s.label}</span>
                                                    <span style={{ color: 'var(--text-muted)' }}>{s.count.toLocaleString()} ({pct.toFixed(1)}%)</span>
                                                </div>
                                                <div style={{ height: 12, background: '#f5f5f5', borderRadius: 6 }}>
                                                    <div style={{ width: `${pct}%`, height: '100%', background: s.color, borderRadius: 6, transition: 'width 0.5s ease' }} />
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        )}

                        {/* Alert Trend */}
                        {tab === 'trend' && (
                            <div className="card">
                                <div className="card-title">
                                    <FontAwesomeIcon icon={faChartBar} className="card-title-icon" />
                                    Daily Alert Trend by Severity
                                </div>
                                <div style={{ display: 'flex', gap: 16, marginBottom: 12, flexWrap: 'wrap' }}>
                                    {[
                                        { label: 'High', color: 'var(--critical)' },
                                        { label: 'Medium', color: 'var(--high)' },
                                        { label: 'Low', color: 'var(--low)' },
                                        { label: 'Informational', color: 'var(--info)' },
                                    ].map(s => (
                                        <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                            <div style={{ width: 10, height: 10, borderRadius: 2, background: s.color }} />{s.label}
                                        </div>
                                    ))}
                                </div>
                                {trend.length === 0 ? (
                                    <div className="empty-state"><div className="empty-state-text">No trend data available</div></div>
                                ) : (
                                    <div>
                                        <div style={{ height: 200, display: 'flex', alignItems: 'flex-end', gap: 3, paddingBottom: 6 }}>
                                            {trend.map((d, i) => {
                                                const total = d.High + d.Medium + d.Low + d.Informational;
                                                const h = (total / maxTrend) * 180;
                                                return (
                                                    <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', height: `${h}px`, minHeight: 2, borderRadius: '3px 3px 0 0', overflow: 'hidden' }}
                                                        title={`${d.date}\nH:${d.High} M:${d.Medium} L:${d.Low}`}>
                                                        <div style={{ flex: d.Informational, background: 'var(--info)', minHeight: d.Informational > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.Low, background: 'var(--low)', minHeight: d.Low > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.Medium, background: 'var(--high)', minHeight: d.Medium > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.High, background: 'var(--critical)', minHeight: d.High > 0 ? 1 : 0 }} />
                                                    </div>
                                                );
                                            })}
                                        </div>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                                            <span>{trend[0]?.date}</span>
                                            <span>{trend[trend.length - 1]?.date}</span>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Silent Rules */}
                        {tab === 'silent' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, alignItems: 'center' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faBellSlash} className="card-title-icon" style={{ color: 'var(--high)' }} />
                                        Silent Detection Rules
                                    </div>
                                    <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
                                        Rules that fired previously but not in the last {days} days
                                    </div>
                                </div>
                                {silentRules.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}>
                                        <div className="empty-state-icon"><FontAwesomeIcon icon={faListCheck} style={{ color: 'var(--low)', opacity: 0.6 }} /></div>
                                        <div className="empty-state-text">All rules appear active — no silent detections found</div>
                                    </div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Rule Name</th>
                                                    <th style={{ width: 100 }}>Severity</th>
                                                    <th style={{ width: 100 }}>Total Alerts</th>
                                                    <th style={{ width: 160 }}>Last Fired</th>
                                                    <th>Days Silent</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {silentRules.map((r, i) => {
                                                    const lastDate = r.last_fired ? new Date(r.last_fired) : null;
                                                    const daysSilent = lastDate ? Math.floor((Date.now() - lastDate.getTime()) / 86400000) : null;
                                                    return (
                                                        <tr key={i}>
                                                            <td style={{ fontWeight: 600, fontSize: 12 }}>{r.name}</td>
                                                            <td><span className={`badge ${sevBadge(r.severity)}`}>{r.severity}</span></td>
                                                            <td>{r.total_alerts.toLocaleString()}</td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{lastDate?.toLocaleDateString() ?? '—'}</td>
                                                            <td>
                                                                <span className={`badge ${daysSilent && daysSilent > 60 ? 'badge-critical' : 'badge-high'}`}>
                                                                    {daysSilent !== null ? `${daysSilent}d` : '—'}
                                                                </span>
                                                            </td>
                                                        </tr>
                                                    );
                                                })}
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
