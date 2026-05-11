import React from 'react';
import { useConfig, useInvestigations, useReports } from '../hooks';
import type { Job } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faHouse,
    faTriangleExclamation,
    faClock,
    faSearch,
    faGear,
    faRocket,
    faFileLines,
    faCheckCircle,
    faSpinner,
    faExclamationTriangle,
} from '@fortawesome/free-solid-svg-icons';
import { AreaChart, Area, ResponsiveContainer } from 'recharts';

function timeAgo(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
}

function statusBadge(status: Job['status']) {
    const map = {
        pending: { label: 'Pending', cls: 'badge-muted' },
        running: { label: 'Running', cls: 'badge-info' },
        completed: { label: 'Done', cls: 'badge-low' },
        failed: { label: 'Failed', cls: 'badge-critical' },
    };
    const b = map[status];
    return <span className={`badge ${b.cls}`}>{b.label}</span>;
}

export default function Dashboard({ onNavigate }: { onNavigate: (p: string) => void }) {
    const { config, loading: cfgLoading } = useConfig();
    const { jobs, loading: jobsLoading, error: jobsError } = useInvestigations(10000);
    const { reports, loading: repsLoading } = useReports();

    const completed = jobs.filter(j => j.status === 'completed');
    const failed = jobs.filter(j => j.status === 'failed');
    const running = jobs.filter(j => j.status === 'running');

    const recent = jobs.slice(0, 6);

    const jobsByDay = React.useMemo(() => {
        const days: { date: string; count: number }[] = [];
        for (let i = 6; i >= 0; i--) {
            const d = new Date();
            d.setDate(d.getDate() - i);
            const dateStr = d.toISOString().split('T')[0];
            days.push({
                date: dateStr.slice(5),
                count: jobs.filter((j: any) => (j.created_at || '').startsWith(dateStr)).length,
            });
        }
        return days;
    }, [jobs]);

    return (
        <div>
            <div className="page-header">
                <div className="page-title">
                    <FontAwesomeIcon icon={faHouse} style={{ marginRight: 12, fontSize: '0.9em', color: 'var(--brand)' }} />
                    Dashboard
                </div>
                <div className="page-subtitle">Sentinel Vigil — Assessment & Coverage Overview</div>
            </div>

            <div className="page-content fade-in">
                {/* ── Auth warning ─────────────────────────────── */}
                {!cfgLoading && config && !config.auth.authenticated && (
                    <div style={{
                        background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)',
                        borderRadius: 'var(--radius-lg)', padding: '12px 16px', marginBottom: 20,
                        color: '#DC2626', fontSize: 12.5, display: 'flex', alignItems: 'center', gap: 10, fontWeight: 500
                    }}>
                        <FontAwesomeIcon icon={faTriangleExclamation} />
                        <div>
                            <strong>Azure authentication failed.</strong>{' '}
                            {config.auth.hint || 'Run az login and restart the backend.'}
                        </div>
                    </div>
                )}
                {/* ── Backend connectivity error ────────────────── */}
                {!jobsLoading && jobsError && (
                    <div style={{
                        background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)',
                        borderRadius: 'var(--radius-lg)', padding: '12px 16px', marginBottom: 20,
                        color: '#DC2626', fontSize: 12.5, display: 'flex', alignItems: 'center', gap: 10, fontWeight: 500
                    }}>
                        <FontAwesomeIcon icon={faTriangleExclamation} />
                        <div>
                            <strong>Backend unreachable.</strong>{' '}
                            {jobsError} — ensure the backend is running and credentials are saved in Settings.
                        </div>
                    </div>
                )}

                {/* ── Metric cards with sparklines ─────────────────── */}
                <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginBottom: 24 }}>
                    {/* Total Investigations */}
                    <div className="card-metric" style={{ flex: 1, minWidth: 160 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                            <div>
                                <div className="card-metric-value">{jobsLoading ? '…' : jobs.length}</div>
                                <div className="card-metric-label">Total Investigations</div>
                            </div>
                            <FontAwesomeIcon icon={faSearch} style={{ color: 'var(--pwc-orange)', opacity: 0.35, fontSize: 18 }} />
                        </div>
                        <div style={{ height: 44, marginTop: 4 }}>
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={jobsByDay} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="sparkGradOrange" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#D04A02" stopOpacity={0.25} />
                                            <stop offset="95%" stopColor="#D04A02" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <Area type="monotone" dataKey="count" stroke="#D04A02" strokeWidth={1.5}
                                          fill="url(#sparkGradOrange)" dot={false} />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Completed */}
                    <div className="card-metric" style={{ flex: 1, minWidth: 160 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                            <div>
                                <div className="card-metric-value" style={{ color: '#27AE60' }}>{jobsLoading ? '…' : completed.length}</div>
                                <div className="card-metric-label">Completed</div>
                            </div>
                            <FontAwesomeIcon icon={faCheckCircle} style={{ color: '#27AE60', opacity: 0.35, fontSize: 18 }} />
                        </div>
                        <div style={{ height: 44, marginTop: 4 }}>
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={jobsByDay} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="sparkGradGreen" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#27AE60" stopOpacity={0.25} />
                                            <stop offset="95%" stopColor="#27AE60" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <Area type="monotone" dataKey="count" stroke="#27AE60" strokeWidth={1.5}
                                          fill="url(#sparkGradGreen)" dot={false} />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Running */}
                    <div className="card-metric" style={{ flex: 1, minWidth: 160 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                            <div>
                                <div className="card-metric-value" style={{ color: '#2980B9' }}>{jobsLoading ? '…' : running.length}</div>
                                <div className="card-metric-label">Running Now</div>
                            </div>
                            <FontAwesomeIcon icon={faSpinner} style={{ color: '#2980B9', opacity: 0.35, fontSize: 18 }} />
                        </div>
                        <div style={{ height: 44, marginTop: 4 }}>
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={jobsByDay} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="sparkGradBlue" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#2980B9" stopOpacity={0.25} />
                                            <stop offset="95%" stopColor="#2980B9" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <Area type="monotone" dataKey="count" stroke="#2980B9" strokeWidth={1.5}
                                          fill="url(#sparkGradBlue)" dot={false} />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Reports */}
                    <div className="card-metric" style={{ flex: 1, minWidth: 160 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                            <div>
                                <div className="card-metric-value" style={{ color: '#7D7D7D' }}>{repsLoading ? '…' : reports.length}</div>
                                <div className="card-metric-label">HTML Reports</div>
                            </div>
                            <FontAwesomeIcon icon={faFileLines} style={{ color: '#7D7D7D', opacity: 0.35, fontSize: 18 }} />
                        </div>
                        <div style={{ height: 44, marginTop: 4 }}>
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={jobsByDay} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="sparkGradGray" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#7D7D7D" stopOpacity={0.25} />
                                            <stop offset="95%" stopColor="#7D7D7D" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <Area type="monotone" dataKey="count" stroke="#7D7D7D" strokeWidth={1.5}
                                          fill="url(#sparkGradGray)" dot={false} />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Failed */}
                    <div className="card-metric" style={{ flex: 1, minWidth: 160 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                            <div>
                                <div className="card-metric-value" style={{ color: '#C0392B' }}>{jobsLoading ? '…' : failed.length}</div>
                                <div className="card-metric-label">Failed</div>
                            </div>
                            <FontAwesomeIcon icon={faExclamationTriangle} style={{ color: '#C0392B', opacity: 0.35, fontSize: 18 }} />
                        </div>
                        <div style={{ height: 44, marginTop: 4 }}>
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={jobsByDay} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="sparkGradRed" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#C0392B" stopOpacity={0.25} />
                                            <stop offset="95%" stopColor="#C0392B" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <Area type="monotone" dataKey="count" stroke="#C0392B" strokeWidth={1.5}
                                          fill="url(#sparkGradRed)" dot={false} />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 20 }}>
                    {/* ── Recent Jobs ─────────────────────────────── */}
                    <div className="card card-elevated">
                        <div className="card-title">
                            <span className="card-title-icon"><FontAwesomeIcon icon={faClock} /></span>
                            Recent Investigations
                        </div>
                        {jobsLoading ? (
                            <div style={{ textAlign: 'center', padding: 20 }}><span className="spinner" /></div>
                        ) : recent.length === 0 ? (
                            <div className="empty-state">
                                <div className="empty-state-icon"><FontAwesomeIcon icon={faSearch} /></div>
                                <div className="empty-state-text">No investigations yet</div>
                                <button className="btn btn-primary" style={{ marginTop: 14 }} onClick={() => onNavigate('investigate')}>
                                    New Investigation
                                </button>
                            </div>
                        ) : (
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead>
                                        <tr>
                                            <th style={{ width: 36 }}></th>
                                            <th>User</th>
                                            <th>Status</th>
                                            <th>Risk</th>
                                            <th>Started</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {recent.map(job => (
                                            <tr key={job.job_id}>
                                                <td style={{ width: 36, paddingRight: 0 }}>
                                                    <div className="avatar avatar-sm avatar-orange">
                                                        {(job.result?.upn || '??').slice(0, 2).toUpperCase()}
                                                    </div>
                                                </td>
                                                <td className="mono" style={{ fontSize: 12 }}>{job.result?.upn || '—'}</td>
                                                <td>{statusBadge(job.status)}</td>
                                                <td>
                                                    {job.result?.risk_level ? (
                                                        <span className={`badge badge-${(job.result.risk_level || '').toLowerCase()}`}>
                                                            {job.result.risk_level}
                                                        </span>
                                                    ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                                                </td>
                                                <td className="text-muted text-xs">{timeAgo(job.created_at)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>

                    {/* ── Config summary ───────────────────────────── */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        <div className="card">
                            <div className="card-title">
                                <span className="card-title-icon"><FontAwesomeIcon icon={faGear} /></span>
                                Configuration
                            </div>
                            {cfgLoading ? <span className="spinner" /> : config ? (
                                <div style={{ fontSize: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
                                    <ConfigRow label="Workspace" value={config.workspace_name || '—'} />
                                    <ConfigRow label="Tenant" value={`${config.tenant_id.slice(0, 8)}…`} />
                                    <ConfigRow label="Auth" value={config.auth.authenticated ? '✅ Active' : '❌ Failed'} />
                                    {Object.entries(config.apis_configured).map(([k, v]) => (
                                        <ConfigRow key={k} label={k.replace('_', ' ').toUpperCase()} value={v ? '✅' : '❌'} />
                                    ))}
                                </div>
                            ) : <span className="text-muted text-sm">Failed to load config</span>}
                        </div>

                        <div className="card">
                            <div className="card-title">
                                <span className="card-title-icon"><FontAwesomeIcon icon={faRocket} /></span>
                                Quick Actions
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                                {[
                                    { label: 'New Investigation', desc: 'Investigate a user',       color: 'var(--pwc-orange)', page: 'investigate' },
                                    { label: 'Enrich IPs',        desc: 'Multi-source threat intel', color: 'var(--info)',       page: 'enrich' },
                                    { label: 'Browse Reports',    desc: 'View saved HTML reports',   color: 'var(--low)',        page: 'reports' },
                                    { label: 'KQL Explorer',      desc: 'AI-powered KQL queries',    color: 'var(--high)',       page: 'kql' },
                                ].map(action => (
                                    <button key={action.page}
                                        onClick={() => onNavigate(action.page)}
                                        style={{
                                            background: 'var(--bg-card)', border: '1px solid var(--border)',
                                            borderRadius: 'var(--radius-lg)', padding: '14px', cursor: 'pointer',
                                            textAlign: 'left', transition: 'all var(--transition)',
                                            display: 'flex', flexDirection: 'column', gap: 4,
                                        }}
                                        onMouseEnter={e => {
                                            (e.currentTarget as HTMLButtonElement).style.borderColor = action.color;
                                            (e.currentTarget as HTMLButtonElement).style.boxShadow = 'var(--shadow-md)';
                                        }}
                                        onMouseLeave={e => {
                                            (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border)';
                                            (e.currentTarget as HTMLButtonElement).style.boxShadow = 'none';
                                        }}
                                    >
                                        <div style={{ fontWeight: 700, fontSize: 12.5, color: 'var(--text-primary)' }}>{action.label}</div>
                                        <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>{action.desc}</div>
                                    </button>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                {/* ── Activity Timeline ────────────────────────── */}
                <div className="card" style={{ marginTop: 20 }}>
                    <div className="card-title">
                        <FontAwesomeIcon icon={faClock} />
                        Activity Timeline
                    </div>
                    <div className="timeline">
                        {jobs.slice(0, 5).map((job: any) => (
                            <div key={job.job_id} className="timeline-item">
                                <div className="timeline-dot" style={{
                                    color: job.status === 'completed' ? 'var(--low)'
                                         : job.status === 'failed'    ? 'var(--critical)'
                                         : job.status === 'running'   ? 'var(--pwc-orange)'
                                         : 'var(--text-muted)',
                                    background: job.status === 'completed' ? 'var(--low)'
                                         : job.status === 'failed'    ? 'var(--critical)'
                                         : job.status === 'running'   ? 'var(--pwc-orange)'
                                         : 'var(--text-muted)',
                                }} />
                                <div className="timeline-content">
                                    <div className="timeline-time">{timeAgo(job.created_at || new Date().toISOString())}</div>
                                    <div className="timeline-text" style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                                        {job.result?.upn || 'Investigation'}
                                        {job.result?.risk_level && (
                                            <span className={`badge badge-${(job.result.risk_level || '').toLowerCase()}`} style={{ fontSize: 10 }}>
                                                {job.result.risk_level}
                                            </span>
                                        )}
                                    </div>
                                </div>
                            </div>
                        ))}
                        {jobs.length === 0 && (
                            <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '8px 0' }}>No activity yet</div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

function ConfigRow({ label, value }: { label: string; value: string }) {
    return (
        <div className="kv-row">
            <span className="kv-label">{label}</span>
            <span className="kv-value">{value}</span>
        </div>
    );
}
