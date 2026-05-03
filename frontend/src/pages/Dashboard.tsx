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
    faGlobe,
    faFileLines,
    faBolt
} from '@fortawesome/free-solid-svg-icons';

function riskColor(level?: string) {
    const map: Record<string, string> = {
        CRITICAL: 'var(--critical)', HIGH: 'var(--high)',
        MEDIUM: 'var(--medium)', LOW: 'var(--low)', INFO: 'var(--info)',
    };
    return map[level || 'INFO'] ?? 'var(--info)';
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

function timeAgo(iso: string) {
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60) return `${Math.floor(diff)}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

export default function Dashboard({ onNavigate }: { onNavigate: (p: string) => void }) {
    const { config, loading: cfgLoading } = useConfig();
    const { jobs, loading: jobsLoading, error: jobsError } = useInvestigations(10000);
    const { reports, loading: repsLoading } = useReports();

    const completed = jobs.filter(j => j.status === 'completed');
    const failed = jobs.filter(j => j.status === 'failed');
    const running = jobs.filter(j => j.status === 'running');

    const recent = jobs.slice(0, 6);

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
                        background: 'rgba(255,71,71,0.08)', border: '1px solid rgba(255,71,71,0.3)',
                        borderRadius: 'var(--radius-md)', padding: '14px 18px', marginBottom: 20,
                        color: 'var(--high)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 12
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
                        background: 'rgba(255,71,71,0.08)', border: '1px solid rgba(255,71,71,0.3)',
                        borderRadius: 'var(--radius-md)', padding: '14px 18px', marginBottom: 20,
                        color: 'var(--high)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 12
                    }}>
                        <FontAwesomeIcon icon={faTriangleExclamation} />
                        <div>
                            <strong>Backend unreachable.</strong>{' '}
                            {jobsError} — ensure the backend is running and credentials are saved in Settings.
                        </div>
                    </div>
                )}

                {/* ── Stat tiles ───────────────────────────────── */}
                <div className="stat-grid" style={{ marginBottom: 24 }}>
                    <div className="stat-tile">
                        <div className="stat-tile-value">{jobsLoading ? '…' : jobs.length}</div>
                        <div className="stat-tile-label">Total Investigations</div>
                    </div>
                    <div className="stat-tile">
                        <div className="stat-tile-value" style={{ color: 'var(--low)' }}>
                            {jobsLoading ? '…' : completed.length}
                        </div>
                        <div className="stat-tile-label">Completed</div>
                    </div>
                    <div className="stat-tile">
                        <div className="stat-tile-value" style={{ color: 'var(--info)' }}>
                            {jobsLoading ? '…' : running.length}
                        </div>
                        <div className="stat-tile-label">Running Now</div>
                    </div>
                    <div className="stat-tile">
                        <div className="stat-tile-value" style={{ color: 'var(--text-secondary)' }}>
                            {repsLoading ? '…' : reports.length}
                        </div>
                        <div className="stat-tile-label">HTML Reports</div>
                    </div>
                    <div className="stat-tile">
                        <div className="stat-tile-value" style={{ color: 'var(--medium)' }}>
                            {jobsLoading ? '…' : failed.length}
                        </div>
                        <div className="stat-tile-label">Failed</div>
                    </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20 }}>
                    {/* ── Recent Jobs ─────────────────────────────── */}
                    <div className="card">
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
                                    Start First Investigation
                                </button>
                            </div>
                        ) : (
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead>
                                        <tr>
                                            <th>User</th>
                                            <th>Status</th>
                                            <th>Risk</th>
                                            <th>Started</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {recent.map(job => (
                                            <tr key={job.job_id}>
                                                <td className="mono" style={{ fontSize: 12 }}>{job.result?.upn || '—'}</td>
                                                <td>{statusBadge(job.status)}</td>
                                                <td>
                                                    {job.result?.risk_level ? (
                                                        <span style={{ color: riskColor(job.result.risk_level), fontWeight: 700, fontSize: 12 }}>
                                                            {job.result.risk_level}
                                                        </span>
                                                    ) : '—'}
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
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                <button className="btn btn-primary" onClick={() => onNavigate('investigate')}>
                                    <FontAwesomeIcon icon={faSearch} style={{ marginRight: 8 }} /> New Investigation
                                </button>
                                <button className="btn btn-secondary" onClick={() => onNavigate('enrich')}>
                                    <FontAwesomeIcon icon={faGlobe} style={{ marginRight: 8 }} /> Enrich IPs
                                </button>
                                <button className="btn btn-secondary" onClick={() => onNavigate('reports')}>
                                    <FontAwesomeIcon icon={faFileLines} style={{ marginRight: 8 }} /> Browse Reports
                                </button>
                                <button className="btn btn-secondary" onClick={() => onNavigate('kql')}>
                                    <FontAwesomeIcon icon={faBolt} style={{ marginRight: 8 }} /> KQL Explorer
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

function ConfigRow({ label, value }: { label: string; value: string }) {
    return (
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
            <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
            <span style={{ color: 'var(--text-primary)', textAlign: 'right' }}>{value}</span>
        </div>
    );
}
