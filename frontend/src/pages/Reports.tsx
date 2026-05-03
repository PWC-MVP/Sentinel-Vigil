import { useState } from 'react';
import { useReports, type Report } from '../hooks';

function formatBytes(bytes: number) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatDate(ts: number) {
    return new Date(ts * 1000).toLocaleString();
}

function ReportRow({ report, onSelect, selected }: {
    report: Report;
    onSelect: (r: Report) => void;
    selected: boolean;
}) {
    const name = report.name.replace('.html', '').replace(/Investigation_Report_Compact_/i, '').replace(/_/g, ' ');
    return (
        <tr
            onClick={() => onSelect(report)}
            style={{ cursor: 'pointer', background: selected ? 'var(--accent-glow)' : undefined }}
        >
            <td>
                <div style={{ fontWeight: 600, fontSize: 12 }}>{name}</div>
                {report.subdirectory && (
                    <div className="text-xs text-muted">{report.subdirectory}</div>
                )}
            </td>
            <td className="text-xs text-muted">{formatBytes(report.size_bytes)}</td>
            <td className="text-xs text-muted">{formatDate(report.created)}</td>
            <td>
                <a
                    href={`/api/reports/${report.relative_path}`}
                    target="_blank"
                    rel="noreferrer"
                    className="btn btn-ghost btn-sm"
                    onClick={e => e.stopPropagation()}
                >
                    ↗ Open
                </a>
            </td>
        </tr>
    );
}

export default function Reports({ onNavigate }: { onNavigate: (p: string) => void }) {
    const { reports, loading, refresh } = useReports();
    const [selected, setSelected] = useState<Report | null>(null);

    return (
        <div>
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                        <div className="page-title">📄 Reports</div>
                        <div className="page-subtitle">Browse and preview generated HTML investigation reports</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                        <button className="btn btn-secondary btn-sm" onClick={refresh}>🔄 Refresh</button>
                        <button className="btn btn-primary btn-sm" onClick={() => onNavigate('investigate')}>
                            + New Investigation
                        </button>
                    </div>
                </div>
            </div>

            <div className="page-content" style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: 20, alignItems: 'start' }}>
                {/* ── Report list ─────────────────────────────── */}
                <div className="card" style={{ padding: 0 }}>
                    <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)' }}>
                        <div className="card-title" style={{ marginBottom: 0 }}>
                            <span className="card-title-icon">📋</span>
                            Reports ({reports.length})
                        </div>
                    </div>
                    {loading ? (
                        <div style={{ textAlign: 'center', padding: 32 }}><span className="spinner" /></div>
                    ) : reports.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-state-icon">📄</div>
                            <div className="empty-state-text">No reports found</div>
                            <button className="btn btn-primary" style={{ marginTop: 14 }} onClick={() => onNavigate('investigate')}>
                                Run Investigation
                            </button>
                        </div>
                    ) : (
                        <div className="data-table-wrap" style={{ border: 'none', borderRadius: 0 }}>
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th>Report</th>
                                        <th>Size</th>
                                        <th>Created</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {reports.map(r => (
                                        <ReportRow
                                            key={r.relative_path}
                                            report={r}
                                            selected={selected?.relative_path === r.relative_path}
                                            onSelect={setSelected}
                                        />
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>

                {/* ── Preview pane ─────────────────────────────── */}
                <div>
                    {selected ? (
                        <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                                <div style={{ fontSize: 13, fontWeight: 600 }}>{selected.name}</div>
                                <a
                                    href={`/api/reports/${selected.relative_path}`}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="btn btn-primary btn-sm"
                                >
                                    ↗ Open Full Screen
                                </a>
                            </div>
                            <iframe
                                src={`/api/reports/${selected.relative_path}`}
                                className="report-preview"
                                title="Report Preview"
                            />
                        </div>
                    ) : (
                        <div className="empty-state" style={{ marginTop: 80 }}>
                            <div className="empty-state-icon">👈</div>
                            <div className="empty-state-text">Select a report to preview it</div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
