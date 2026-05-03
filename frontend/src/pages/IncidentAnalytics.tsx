import { useState, useEffect } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faChartBar, faClock, faUsers, faShieldHalved,
    faArrowTrendDown, faFilePdf, faFileCode, faRefresh
} from '@fortawesome/free-solid-svg-icons';

interface Summary { total: number; open: number; closed: number; high_count: number; avg_first_resp_hours: number; }
interface MTTR {
    avg_hours: number; median_hours: number; p90_hours: number; p95_hours: number;
    min_hours: number; max_hours: number; total_closed: number;
    by_severity: { severity: string; avg_hours: number; count: number }[];
}
interface DayPoint { date: string; High: number; Medium: number; Low: number; Informational: number; }
interface Owner { name: string; total: number; open: number; closed: number; }
interface SLA { severity: string; sla_target_hours: number; total: number; sla_met: number; sla_breached: number; compliance_rate: number; avg_mttr: number; }

function sevColor(s: string) {
    if (s === 'High') return 'var(--critical)';
    if (s === 'Medium') return 'var(--high)';
    if (s === 'Low') return 'var(--low)';
    return 'var(--info)';
}

function formatHours(h: number) {
    if (h < 1) return `${Math.round(h * 60)}m`;
    if (h < 48) return `${h.toFixed(1)}h`;
    return `${(h / 24).toFixed(1)}d`;
}

function MttrGauge({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
    const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
    return (
        <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>{label}</div>
            <div style={{ position: 'relative', width: 80, height: 80, margin: '0 auto' }}>
                <svg viewBox="0 0 80 80" style={{ transform: 'rotate(-90deg)' }}>
                    <circle cx="40" cy="40" r="32" fill="none" stroke="#f0f0f0" strokeWidth="8" />
                    <circle cx="40" cy="40" r="32" fill="none" stroke={color} strokeWidth="8"
                        strokeDasharray={`${pct * 2.01} 201`} strokeLinecap="round" />
                </svg>
                <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column' }}>
                    <div style={{ fontSize: 13, fontWeight: 800, color, lineHeight: 1 }}>{formatHours(value)}</div>
                </div>
            </div>
        </div>
    );
}

export default function IncidentAnalytics() {
    const [tab, setTab] = useState<'mttr' | 'trends' | 'owners' | 'sla'>('mttr');
    const [days, setDays] = useState(30);
    const [summary, setSummary] = useState<Summary | null>(null);
    const [mttr, setMttr] = useState<MTTR | null>(null);
    const [trends, setTrends] = useState<DayPoint[]>([]);
    const [owners, setOwners] = useState<Owner[]>([]);
    const [sla, setSla] = useState<SLA[]>([]);
    const [loading, setLoading] = useState(true);
    const [isExporting, setIsExporting] = useState(false);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [sum, mt, tr, ow, sl] = await Promise.all([
                axios.get(`/api/incident-analytics/summary?days=${days}`),
                axios.get(`/api/incident-analytics/mttr?days=${days}`),
                axios.get(`/api/incident-analytics/trends?days=${days}`),
                axios.get(`/api/incident-analytics/owners?days=${days}`),
                axios.get(`/api/incident-analytics/sla?days=${days}`),
            ]);
            setSummary(sum.data);
            setMttr(mt.data);
            setTrends(tr.data.daily || []);
            setOwners(ow.data.owners || []);
            setSla(sl.data.sla || []);
        } catch (e) {
            console.error('IncidentAnalytics fetch failed', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, [days]);

    const maxOwner = Math.max(...owners.map(o => o.total), 1);
    const maxTrend = Math.max(...trends.map(d => d.High + d.Medium + d.Low + d.Informational), 1);
    const mttrMax = Math.max(mttr?.p95_hours ?? 1, 1);

    const handleExport = async (format: 'pdf' | 'html') => {
        setIsExporting(true);
        const html = `<div style="font-family:Inter,sans-serif;padding:40px;color:#2D2D2D">
            <h1 style="color:#D04A02;border-bottom:3px solid #D04A02;padding-bottom:16px">Incident Analytics Report</h1>
            <p>Period: Last ${days} days · Generated: ${new Date().toLocaleString()}</p>
            <h2>MTTR Summary</h2>
            <p>Avg MTTR: <strong>${formatHours(mttr?.avg_hours ?? 0)}</strong> · Median: <strong>${formatHours(mttr?.median_hours ?? 0)}</strong> · P90: <strong>${formatHours(mttr?.p90_hours ?? 0)}</strong></p>
            <h2>SLA Compliance</h2>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#F7F7F7"><th style="padding:10px;border:1px solid #E5E5E5;text-align:left">Severity</th>
                <th style="padding:10px;border:1px solid #E5E5E5">SLA Target</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Met</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Breached</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Rate</th></tr>
                ${sla.map(r => `<tr>
                    <td style="padding:8px;border:1px solid #E5E5E5">${r.severity}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${r.sla_target_hours}h</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;color:#27AE60">${r.sla_met}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;color:#C0392B">${r.sla_breached}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;font-weight:700">${r.compliance_rate}%</td>
                </tr>`).join('')}
            </table></div>`;
        try {
            const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const res = await axios.post(endpoint, { html, filename: `Incident_Analytics_${days}d.${format}` }, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url; a.download = `Incident_Analytics.${format}`; a.click(); a.remove();
        } catch (e: any) { alert(`Export failed: ${e.message}`); }
        finally { setIsExporting(false); }
    };

    const Skeleton = () => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 16 }}>
                {[1,2,3,4,5].map(i => <div key={i} className="stat-tile"><div className="skeleton skeleton-title" /><div className="skeleton skeleton-text" /></div>)}
            </div>
            <div className="card"><div className="skeleton skeleton-box" style={{ height: 240 }} /></div>
        </div>
    );

    return (
        <div>
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faChartBar} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Incident Analytics
                        </div>
                        <div className="page-subtitle">MTTR, SLA compliance, daily trends, and owner workload distribution</div>
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
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 16 }}>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--brand)' }}>
                                <div className="stat-tile-label">Total Incidents</div>
                                <div className="stat-tile-value">{(summary?.total ?? 0).toLocaleString()}</div>
                                <div className="text-xs text-muted">{summary?.open} open · {summary?.closed} closed</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--info)' }}>
                                <div className="stat-tile-label">Avg MTTR</div>
                                <div className="stat-tile-value" style={{ color: 'var(--info)', fontSize: 22 }}>{formatHours(mttr?.avg_hours ?? 0)}</div>
                                <div className="text-xs text-muted">Mean time to resolve</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--low)' }}>
                                <div className="stat-tile-label">Median MTTR</div>
                                <div className="stat-tile-value" style={{ color: 'var(--low)', fontSize: 22 }}>{formatHours(mttr?.median_hours ?? 0)}</div>
                                <div className="text-xs text-muted">P50 resolution time</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--high)' }}>
                                <div className="stat-tile-label">P90 MTTR</div>
                                <div className="stat-tile-value" style={{ color: 'var(--high)', fontSize: 22 }}>{formatHours(mttr?.p90_hours ?? 0)}</div>
                                <div className="text-xs text-muted">90th percentile</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--critical)' }}>
                                <div className="stat-tile-label">High Severity</div>
                                <div className="stat-tile-value" style={{ color: 'var(--critical)' }}>{(summary?.high_count ?? 0).toLocaleString()}</div>
                                <div className="text-xs text-muted">Immediate escalation</div>
                            </div>
                        </div>

                        {/* Tabs */}
                        <div className="tabs" style={{ marginBottom: 0 }}>
                            {([
                                { id: 'mttr', label: 'MTTR Analysis', icon: faClock },
                                { id: 'trends', label: 'Daily Trends', icon: faChartBar },
                                { id: 'owners', label: 'Owner Workload', icon: faUsers },
                                { id: 'sla', label: 'SLA Compliance', icon: faShieldHalved },
                            ] as const).map(t => (
                                <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                                    <FontAwesomeIcon icon={t.icon} style={{ marginRight: 8 }} />{t.label}
                                </button>
                            ))}
                        </div>

                        {/* MTTR */}
                        {tab === 'mttr' && (
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20 }}>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faClock} className="card-title-icon" />
                                        MTTR Percentile Distribution
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-around', padding: '20px 0 10px', flexWrap: 'wrap', gap: 16 }}>
                                        <MttrGauge label="Min" value={mttr?.min_hours ?? 0} max={mttrMax} color="var(--low)" />
                                        <MttrGauge label="Avg" value={mttr?.avg_hours ?? 0} max={mttrMax} color="var(--info)" />
                                        <MttrGauge label="Median (P50)" value={mttr?.median_hours ?? 0} max={mttrMax} color="var(--brand)" />
                                        <MttrGauge label="P90" value={mttr?.p90_hours ?? 0} max={mttrMax} color="var(--high)" />
                                        <MttrGauge label="P95" value={mttr?.p95_hours ?? 0} max={mttrMax} color="var(--critical)" />
                                        <MttrGauge label="Max" value={mttr?.max_hours ?? 0} max={mttrMax} color="#7D7D7D" />
                                    </div>
                                    <div style={{ textAlign: 'center', marginTop: 8, fontSize: 11, color: 'var(--text-muted)' }}>
                                        Based on {(mttr?.total_closed ?? 0).toLocaleString()} closed incidents
                                    </div>
                                </div>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faArrowTrendDown} className="card-title-icon" />
                                        MTTR by Severity
                                    </div>
                                    {(mttr?.by_severity ?? []).length === 0 ? (
                                        <div className="empty-state"><div className="empty-state-text">No MTTR data by severity</div></div>
                                    ) : (
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                                            {(mttr?.by_severity ?? []).map(s => (
                                                <div key={s.severity}>
                                                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
                                                        <span style={{ fontWeight: 700, color: sevColor(s.severity) }}>{s.severity}</span>
                                                        <span style={{ color: 'var(--text-muted)' }}>{formatHours(s.avg_hours)} avg · {s.count} incidents</span>
                                                    </div>
                                                    <div style={{ height: 10, background: '#f5f5f5', borderRadius: 5 }}>
                                                        <div style={{ width: `${Math.min((s.avg_hours / mttrMax) * 100, 100)}%`, height: '100%', background: sevColor(s.severity), borderRadius: 5, transition: 'width 0.5s' }} />
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Daily Trends */}
                        {tab === 'trends' && (
                            <div className="card">
                                <div className="card-title">
                                    <FontAwesomeIcon icon={faChartBar} className="card-title-icon" />
                                    Daily Incident Creation by Severity
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
                                {trends.length === 0 ? (
                                    <div className="empty-state"><div className="empty-state-text">No trend data</div></div>
                                ) : (
                                    <div>
                                        <div style={{ height: 220, display: 'flex', alignItems: 'flex-end', gap: 3, paddingBottom: 6 }}>
                                            {trends.map((d, i) => {
                                                const total = d.High + d.Medium + d.Low + d.Informational;
                                                const h = (total / maxTrend) * 200;
                                                return (
                                                    <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', height: `${Math.max(h, 2)}px`, borderRadius: '3px 3px 0 0', overflow: 'hidden', cursor: 'default' }}
                                                        title={`${d.date}\nH:${d.High}  M:${d.Medium}  L:${d.Low}  I:${d.Informational}`}>
                                                        <div style={{ flex: d.Informational, background: 'var(--info)', minHeight: d.Informational > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.Low, background: 'var(--low)', minHeight: d.Low > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.Medium, background: 'var(--high)', minHeight: d.Medium > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.High, background: 'var(--critical)', minHeight: d.High > 0 ? 1 : 0 }} />
                                                    </div>
                                                );
                                            })}
                                        </div>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)' }}>
                                            <span>{trends[0]?.date}</span>
                                            <span>{trends[trends.length - 1]?.date}</span>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Owners */}
                        {tab === 'owners' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faUsers} className="card-title-icon" />
                                        Incident Workload by Owner
                                    </div>
                                </div>
                                {owners.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}><div className="empty-state-text">No owner data available</div></div>
                                ) : (
                                    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
                                        {owners.map(o => (
                                            <div key={o.name} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                                                <div style={{ width: 200, fontSize: 12, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0 }}
                                                    title={o.name}>{o.name}</div>
                                                <div style={{ flex: 1, height: 22, background: '#f5f5f5', borderRadius: 4, overflow: 'hidden', position: 'relative' }}>
                                                    <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: `${(o.total / maxOwner) * 100}%`, background: 'linear-gradient(90deg, var(--brand) 0%, #ff8c42 100%)', borderRadius: 4, transition: 'width 0.5s' }} />
                                                    <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', paddingLeft: 8, fontSize: 11, color: '#fff', fontWeight: 700, zIndex: 1 }}>
                                                        {o.total}
                                                    </div>
                                                </div>
                                                <div style={{ display: 'flex', gap: 12, fontSize: 11, flexShrink: 0, width: 120 }}>
                                                    <span style={{ color: 'var(--critical)' }}>{o.open} open</span>
                                                    <span style={{ color: 'var(--text-muted)' }}>{o.closed} closed</span>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* SLA */}
                        {tab === 'sla' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, alignItems: 'center' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" style={{ color: 'var(--brand)' }} />
                                        SLA Compliance (High=4h, Medium=8h, Low=24h, Info=72h)
                                    </div>
                                </div>
                                {sla.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}><div className="empty-state-text">No SLA data available</div></div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Severity</th>
                                                    <th style={{ width: 110 }}>SLA Target</th>
                                                    <th style={{ width: 80 }}>Total</th>
                                                    <th style={{ width: 80 }}>Met</th>
                                                    <th style={{ width: 90 }}>Breached</th>
                                                    <th style={{ width: 100 }}>Avg MTTR</th>
                                                    <th>Compliance</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {sla.map(r => (
                                                    <tr key={r.severity}>
                                                        <td style={{ fontWeight: 700, color: sevColor(r.severity) }}>{r.severity}</td>
                                                        <td style={{ fontSize: 12 }}>{r.sla_target_hours}h</td>
                                                        <td>{r.total}</td>
                                                        <td style={{ color: 'var(--low)', fontWeight: 600 }}>{r.sla_met}</td>
                                                        <td style={{ color: r.sla_breached > 0 ? 'var(--critical)' : 'var(--text-muted)', fontWeight: 600 }}>{r.sla_breached}</td>
                                                        <td style={{ fontSize: 12 }}>{formatHours(r.avg_mttr)}</td>
                                                        <td style={{ width: 220 }}>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                                <div style={{ flex: 1, height: 10, background: '#f5f5f5', borderRadius: 5 }}>
                                                                    <div style={{ width: `${r.compliance_rate}%`, height: '100%', background: r.compliance_rate >= 80 ? 'var(--low)' : r.compliance_rate >= 50 ? 'var(--high)' : 'var(--critical)', borderRadius: 5 }} />
                                                                </div>
                                                                <span style={{ fontSize: 12, fontWeight: 700, color: r.compliance_rate >= 80 ? 'var(--low)' : 'var(--critical)', minWidth: 42 }}>{r.compliance_rate}%</span>
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
                    </div>
                )}
            </div>
        </div>
    );
}
