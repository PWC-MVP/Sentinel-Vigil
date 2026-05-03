import { useState, useEffect, useRef } from 'react';
import {
    startInvestigation, getInvestigation, createInvestigationWS,
    type Job, type JobUpdate, type InvestigationResult, type IPIntelligence,
} from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faSearch,
    faScrewdriverWrench,
    faRocket,
    faLightbulb,
    faTowerBroadcast,
    faChartPie,
    faGlobe,
    faLock,
    faUser,
    faTriangleExclamation,
    faShieldHalved,
    faLocationDot,
    faBuilding,
    faCircleCheck,
    faCircleXmark,
    faBurst,
    faFingerprint,
    faLaptop,
    faCloud,
    faClockRotateLeft,
    faMobileScreenButton,
    faFileLines,
    faRobot,
    faChevronDown,
    faChevronUp,
    faFilePdf,
    faFileCode
} from '@fortawesome/free-solid-svg-icons';

// ── Risk colour helper ───────────────────────────────────────────────────────
function riskClass(level?: string) {
    const map: Record<string, string> = {
        CRITICAL: 'badge-critical', HIGH: 'badge-high',
        MEDIUM: 'badge-medium', LOW: 'badge-low', INFO: 'badge-info',
    };
    return map[level || 'INFO'] ?? 'badge-info';
}



// ── IP card ──────────────────────────────────────────────────────────────────
function IPCard({ ip }: { ip: IPIntelligence }) {
    const cardClass = ip.threat_detected ? 'threat' : ip.anomaly_type ? 'anomaly' : '';
    return (
        <div className={`ip-card ${cardClass}`}>
            <div className="ip-addr">{ip.ip}</div>
            <div className="ip-meta">
                <FontAwesomeIcon icon={faLocationDot} style={{ marginRight: 6, fontSize: 10, opacity: 0.7 }} />
                {[ip.city, ip.region, ip.country].filter(Boolean).join(', ')}<br />
                <FontAwesomeIcon icon={faBuilding} style={{ marginRight: 6, fontSize: 10, opacity: 0.7 }} />
                {ip.org || ip.asn || 'Unknown'}<br />
                {ip.threat_detected && <span style={{ color: 'var(--critical)' }}>
                    <FontAwesomeIcon icon={faTriangleExclamation} style={{ marginRight: 6 }} />
                    Threat Intel Match
                </span>}
            </div>
            <div className="ip-flags">
                {ip.threat_detected && <span className="badge badge-critical">THREAT</span>}
                {ip.anomaly_type && <span className="badge badge-medium">ANOMALY</span>}
                {ip.is_vpn && <span className="badge badge-muted">VPN</span>}
                {ip.is_tor && <span className="badge badge-high">TOR</span>}
                {ip.is_proxy && <span className="badge badge-muted">PROXY</span>}
                {(ip.abuse_confidence_score ?? 0) > 50 && (
                    <span className="badge badge-high">ABUSE {ip.abuse_confidence_score}%</span>
                )}
            </div>
        </div>
    );
}

// ── Inline Results ────────────────────────────────────────────────────────────
function ResultsPanel({ result }: { result: InvestigationResult }) {
    const [tab, setTab] = useState<'overview' | 'ips' | 'signins' | 'activity' | 'cloud' | 'identity' | 'raw'>('overview');
    const [exporting, setExporting] = useState(false);

    const handleExport = async (type: 'pdf' | 'html') => {
        setExporting(true);
        try {
            const endpoint = type === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            // We need a simple way to get the HTML of the results panel.
            // Since we can't easily scrape the whole complex React state to HTML here,
            // we'll use the report_path if available, or generate a simple one.

            let payload: any = { filename: `Investigation_${result.upn}_${new Date().toISOString().slice(0, 10)}.${type}` };

            if (type === 'html' && !result.report_path) {
                // If HTML is requested but no report was pre-generated, use the new on-demand generator
                const resp = await fetch('/api/investigations/export-html-report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(result)
                });
                if (!resp.ok) throw new Error("HTML report generation failed");
                const blob = await resp.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = payload.filename;
                a.click();
                return;
            }

            if (result.report_path) {
                payload.file_path = result.report_path;
            } else {
                // Fallback for PDF if no report was generated
                payload.html = `<html><body><h1>Investigation: ${result.upn}</h1><pre>${JSON.stringify(result, null, 2)}</pre></body></html>`;
            }

            const resp = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!resp.ok) throw new Error(`${type.toUpperCase()} export failed`);

            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = payload.filename;
            a.click();
        } catch (e) {
            console.error(e);
            alert(`Failed to export ${type.toUpperCase()}`);
        } finally {
            setExporting(false);
        }
    };

    return (
        <div style={{ marginTop: 24 }}>
            <div className="tabs">
                {(['overview', 'ips', 'signins', 'activity', 'cloud', 'identity', 'raw'] as const).map(t => (
                    <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
                        {t === 'overview' && <><FontAwesomeIcon icon={faChartPie} style={{ marginRight: 8 }} /> Overview</>}
                        {t === 'ips' && <><FontAwesomeIcon icon={faGlobe} style={{ marginRight: 8 }} /> IPs ({result.ip_intelligence.length})</>}
                        {t === 'signins' && <><FontAwesomeIcon icon={faLock} style={{ marginRight: 8 }} /> Sign-ins</>}
                        {t === 'activity' && <><FontAwesomeIcon icon={faClockRotateLeft} style={{ marginRight: 8 }} /> Activity</>}
                        {t === 'cloud' && <><FontAwesomeIcon icon={faCloud} style={{ marginRight: 8 }} /> Cloud Apps ({result.cloud_app_events?.length || 0})</>}
                        {t === 'identity' && <><FontAwesomeIcon icon={faFingerprint} style={{ marginRight: 8 }} /> Identity</>}
                        {t === 'raw' && <><FontAwesomeIcon icon={faScrewdriverWrench} style={{ marginRight: 8 }} /> Raw JSON</>}
                    </button>
                ))}
                <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                    <button className="btn btn-ghost btn-sm" disabled={exporting} onClick={() => handleExport('pdf')}>
                        <FontAwesomeIcon icon={faFilePdf} style={{ marginRight: 6 }} /> PDF
                    </button>
                    <button className="btn btn-ghost btn-sm" disabled={exporting} onClick={() => handleExport('html')}>
                        <FontAwesomeIcon icon={faFileCode} style={{ marginRight: 6 }} /> HTML
                    </button>
                </div>
            </div>

            {tab === 'overview' && (
                <div className="fade-in">
                    {/* Risk level */}
                    <div className={`risk-gauge ${result.risk_level}`} style={{ marginBottom: 16 }}>
                        <div>
                            <div className="text-muted text-xs" style={{ marginBottom: 4 }}>RISK LEVEL</div>
                            <div className={`risk-level-text ${result.risk_level}`}>{result.risk_level}</div>
                        </div>
                        <div style={{ flex: 1 }}>
                            {result.risk_factors.map((f, i) => (
                                <div key={i} style={{ fontSize: 12, marginBottom: 3 }}>
                                    <FontAwesomeIcon icon={faBurst} style={{ marginRight: 8, fontSize: 10 }} />
                                    {f}
                                </div>
                            ))}
                            {result.mitigating_factors.map((f, i) => (
                                <div key={i} style={{ fontSize: 12, color: 'var(--low)', marginBottom: 3 }}>
                                    <FontAwesomeIcon icon={faCircleCheck} style={{ marginRight: 8, fontSize: 10 }} />
                                    {f}
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Key metrics */}
                    <div className="stat-grid" style={{ marginBottom: 20 }}>
                        <div className="stat-tile">
                            <div className="stat-tile-value">{result.anomalies.length}</div>
                            <div className="stat-tile-label">Anomalies</div>
                        </div>
                        <div className="stat-tile">
                            <div className="stat-tile-value">{result.signin_events.total_signins}</div>
                            <div className="stat-tile-label">Total Sign-ins</div>
                        </div>
                        <div className="stat-tile">
                            <div className="stat-tile-value" style={{ color: result.signin_events.total_failures > 0 ? 'var(--high)' : undefined }}>
                                {result.signin_events.total_failures}
                            </div>
                            <div className="stat-tile-label">Failures</div>
                        </div>
                        <div className="stat-tile">
                            <div className="stat-tile-value">{result.ip_intelligence.length}</div>
                            <div className="stat-tile-label">IPs Analyzed</div>
                        </div>
                        <div className="stat-tile">
                            <div className="stat-tile-value" style={{ color: result.incidents.length > 0 ? 'var(--critical)' : undefined }}>
                                {result.incidents.length}
                            </div>
                            <div className="stat-tile-label">Incidents</div>
                        </div>
                    </div>

                    {result.ai_summary && (
                        <div className="card" style={{ marginBottom: 20, borderLeft: '4px solid var(--brand)', background: 'rgba(56, 139, 253, 0.05)' }}>
                            <div className="card-title" style={{ color: 'var(--brand)' }}>
                                <FontAwesomeIcon icon={faRobot} className="card-title-icon" />
                                AI Executive Analysis
                            </div>
                            <div style={{ fontSize: 13, lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
                                {result.ai_summary}
                            </div>
                        </div>
                    )}

                    {/* User profile */}
                    {result.user_profile && (
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faUser} className="card-title-icon" />
                                User Profile
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 13 }}>
                                <InfoRow label="Name" value={result.user_profile.display_name} />
                                <InfoRow label="Title" value={result.user_profile.job_title} />
                                <InfoRow label="Department" value={result.user_profile.department} />
                                <InfoRow label="Location" value={result.user_profile.office_location} />
                                <InfoRow label="Type" value={result.user_profile.user_type} />
                                <InfoRow label="Enabled" value={result.user_profile.account_enabled ? '✅ Yes' : '❌ No'} />
                            </div>
                        </div>
                    )}

                    {/* MFA */}
                    {result.mfa_status && (
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faFingerprint} className="card-title-icon" />
                                MFA Status
                            </div>
                            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                                <span className={`badge ${result.mfa_status.mfa_enabled ? 'badge-low' : 'badge-critical'}`}>
                                    MFA {result.mfa_status.mfa_enabled ? 'ENABLED' : 'DISABLED'}
                                </span>
                                {result.mfa_status.has_fido2 && <span className="badge badge-low">FIDO2</span>}
                                {result.mfa_status.has_authenticator && <span className="badge badge-info">Authenticator</span>}
                                {result.mfa_status.methods.map(m => (
                                    <span key={m} className="badge badge-muted">{m.replace('AuthenticationMethod', '')}</span>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Anomalies */}
                    {result.anomalies.length > 0 && (
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faBurst} className="card-title-icon" />
                                Anomaly Detections ({result.anomalies.length})
                            </div>
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead>
                                        <tr><th>Type</th><th>Value</th><th>Severity</th><th>Country</th><th>Hits</th></tr>
                                    </thead>
                                    <tbody>
                                        {result.anomalies.slice(0, 10).map((a, i) => (
                                            <tr key={i}>
                                                <td className="mono text-xs">{a.AnomalyType}</td>
                                                <td className="mono text-xs">{a.Value}</td>
                                                <td><span className={`badge ${riskClass(a.Severity)}`}>{a.Severity}</span></td>
                                                <td>
                                                    {a.Country || '—'}
                                                    {a.CountryNovelty && (
                                                        <span className="badge badge-medium" style={{ marginLeft: 6, fontSize: 9 }}>NEW</span>
                                                    )}
                                                </td>
                                                <td>{a.ArtifactHits}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Incidents */}
                    {result.incidents.length > 0 && (
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" />
                                Security Incidents ({result.incidents.length})
                            </div>
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead>
                                        <tr><th>Title</th><th>Severity</th><th>Status</th><th>Created</th></tr>
                                    </thead>
                                    <tbody>
                                        {result.incidents.map((inc, i) => (
                                            <tr key={i}>
                                                <td>
                                                    {inc.ProviderIncidentUrl
                                                        ? <a href={inc.ProviderIncidentUrl} target="_blank" rel="noreferrer" style={{ color: 'var(--text-link)' }}>{inc.Title}</a>
                                                        : inc.Title}
                                                </td>
                                                <td><span className={`badge ${riskClass(inc.Severity)}`}>{inc.Severity}</span></td>
                                                <td>{inc.Status}</td>
                                                <td className="text-xs text-muted">{inc.CreatedTime?.slice(0, 10)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {result.report_path && (
                        <div style={{ padding: '12px 16px', background: 'var(--risk-low-bg)', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(63,185,80,0.3)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 10 }}>
                            <FontAwesomeIcon icon={faCircleCheck} style={{ color: 'var(--low)' }} />
                            <span>HTML Report generated. View it in the <strong>Reports</strong> tab.</span>
                        </div>
                    )}
                </div>
            )}

            {tab === 'ips' && (
                <div className="fade-in">
                    {result.ip_intelligence.length === 0 ? (
                        <div className="empty-state"><div className="empty-state-text">No IP data collected</div></div>
                    ) : (
                        <div className="ip-grid">
                            {result.ip_intelligence.map(ip => <IPCard key={ip.ip} ip={ip} />)}
                        </div>
                    )}
                </div>
            )}

            {tab === 'signins' && (
                <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    <div className="card">
                        <div className="card-title">
                            <FontAwesomeIcon icon={faLaptop} className="card-title-icon" />
                            By Application
                        </div>
                        <div className="data-table-wrap">
                            <table className="data-table">
                                <thead><tr><th>App</th><th>Sign-ins</th><th>Failures</th></tr></thead>
                                <tbody>
                                    {result.signin_events.applications.map((a, i) => (
                                        <tr key={i}>
                                            <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.AppDisplayName}</td>
                                            <td>{a.SignInCount}</td>
                                            <td style={{ color: (a.FailureCount ?? 0) > 0 ? 'var(--high)' : undefined }}>{a.FailureCount}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div className="card">
                        <div className="card-title">
                            <FontAwesomeIcon icon={faLocationDot} className="card-title-icon" />
                            By Location
                        </div>
                        <div className="data-table-wrap">
                            <table className="data-table">
                                <thead><tr><th>Location</th><th>Sign-ins</th></tr></thead>
                                <tbody>
                                    {result.signin_events.locations.map((l, i) => (
                                        <tr key={i}>
                                            <td>{l.Location}</td>
                                            <td>{l.SignInCount}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}

            {tab === 'activity' && (
                <div className="fade-in">
                    <div className="card" style={{ marginBottom: 16 }}>
                        <div className="card-title">
                            <FontAwesomeIcon icon={faClockRotateLeft} className="card-title-icon" />
                            Azure AD Audit Logs ({result.audit_events.length})
                        </div>
                        {result.audit_events.length === 0 ? (
                            <div className="empty-state">No audit logs found</div>
                        ) : (
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead><tr><th>Category</th><th>Result</th><th>Total</th><th>Operations</th></tr></thead>
                                    <tbody>
                                        {result.audit_events.map((a, i) => (
                                            <tr key={i}>
                                                <td>{a.Category}</td>
                                                <td><span className={`badge ${a.Result === 'success' || a.Result === 'Success' ? 'badge-low' : 'badge-high'}`}>{a.Result}</span></td>
                                                <td>{a.Count}</td>
                                                <td className="text-xs">{a.Operations?.slice(0, 3).join(', ')}{(a.Operations?.length || 0) > 3 ? '...' : ''}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>

                    <div className="card">
                        <div className="card-title">
                            <FontAwesomeIcon icon={faFileLines} className="card-title-icon" />
                            Office 365 Activity ({result.office_events.length})
                        </div>
                        {result.office_events.length === 0 ? (
                            <div className="empty-state">No Office activity found</div>
                        ) : (
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead><tr><th>Workload</th><th>Operation</th><th>Activity Count</th></tr></thead>
                                    <tbody>
                                        {result.office_events.map((o, i) => (
                                            <tr key={i}>
                                                <td>{o.RecordType}</td>
                                                <td>{o.Operation}</td>
                                                <td>{o.ActivityCount}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {tab === 'cloud' && (
                <div className="fade-in">
                    <div className="card">
                        <div className="card-title">
                            <FontAwesomeIcon icon={faCloud} className="card-title-icon" />
                            Cloud App Events (Defender for Cloud Apps)
                        </div>
                        {!result.cloud_app_events || result.cloud_app_events.length === 0 ? (
                            <div className="empty-state">No cloud app events found</div>
                        ) : (
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead><tr><th>Application</th><th>Action Type</th><th>Count</th><th>Flags</th></tr></thead>
                                    <tbody>
                                        {result.cloud_app_events.map((c, i) => (
                                            <tr key={i}>
                                                <td>{c.Application}</td>
                                                <td>{c.ActionType}</td>
                                                <td>{c.Count}</td>
                                                <td>
                                                    {c.IsAdmin === true || c.IsAdmin?.toString() === 'True' ? <span className="badge badge-high" style={{ marginRight: 4 }}>ADMIN</span> : null}
                                                    {c.IsExternal === true || c.IsExternal?.toString() === 'True' ? <span className="badge badge-medium">EXTERNAL</span> : null}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {tab === 'identity' && (
                <div className="fade-in">
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
                        <div className="card">
                            <div className="card-title">
                                <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" />
                                Entra ID Risk Status
                            </div>
                            <div style={{ marginBottom: 12 }}>
                                <div className="text-xs text-muted">OVERALL RISK</div>
                                <div style={{ fontSize: 18, fontWeight: 'bold' }}>
                                    <span className={`badge ${riskClass(result.risk_profile?.riskLevel?.toUpperCase())}`} style={{ fontSize: 14 }}>
                                        {result.risk_profile?.riskLevel || 'NONE'}
                                    </span>
                                </div>
                            </div>
                            <div>
                                <div className="text-xs text-muted">RISK STATE</div>
                                <div style={{ fontWeight: 600 }}>{result.risk_profile?.riskState || 'No active risk'}</div>
                            </div>
                        </div>

                        <div className="card">
                            <div className="card-title">
                                <FontAwesomeIcon icon={faMobileScreenButton} className="card-title-icon" />
                                Registered Devices ({result.devices.length})
                            </div>
                            {result.devices.length === 0 ? (
                                <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                                    No devices registered in Entra ID / Intune
                                </div>
                            ) : (
                                <div className="data-table-wrap">
                                    <table className="data-table">
                                        <thead><tr><th>Device</th><th>OS</th><th>Compliant</th></tr></thead>
                                        <tbody>
                                            {result.devices.slice(0, 5).map((d, i) => (
                                                <tr key={i}>
                                                    <td>{d.displayName}</td>
                                                    <td className="text-xs">{d.operatingSystem}</td>
                                                    <td>{d.isCompliant ? '✅' : '❌'}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    </div>

                    {result.risk_detections.length > 0 && (
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faTriangleExclamation} className="card-title-icon" />
                                Recent Risk Detections
                            </div>
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead><tr><th>Type</th><th>Level</th><th>IP</th><th>Date</th></tr></thead>
                                    <tbody>
                                        {result.risk_detections.map((rd, i) => (
                                            <tr key={i}>
                                                <td>{rd.riskEventType}</td>
                                                <td><span className={`badge ${riskClass(rd.riskLevel?.toUpperCase())}`}>{rd.riskLevel}</span></td>
                                                <td className="mono text-xs">{rd.ipAddress}</td>
                                                <td className="text-muted text-xs">{rd.detectedDateTime?.slice(0, 10)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {result.risky_signins.length > 0 && (
                        <div className="card">
                            <div className="card-title">
                                <FontAwesomeIcon icon={faLock} className="card-title-icon" />
                                Risky Sign-ins
                            </div>
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead><tr><th>Date</th><th>App</th><th>Risk Level</th><th>State</th></tr></thead>
                                    <tbody>
                                        {result.risky_signins.map((rs, i) => (
                                            <tr key={i}>
                                                <td className="text-xs">{rs.createdDateTime?.slice(0, 16).replace('T', ' ')}</td>
                                                <td>{rs.appDisplayName}</td>
                                                <td><span className={`badge ${riskClass(rs.riskLevelDuringSignIn?.toUpperCase())}`}>{rs.riskLevelDuringSignIn}</span></td>
                                                <td className="text-xs">{rs.riskState}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {tab === 'raw' && (
                <div className="fade-in">
                    <pre style={{
                        background: 'var(--bg-base)', border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-md)', padding: 16, fontSize: 11,
                        overflow: 'auto', maxHeight: 500, color: 'var(--text-secondary)',
                    }}>
                        {JSON.stringify(result, null, 2)}
                    </pre>
                </div>
            )}
        </div>
    );
}

function InfoRow({ label, value }: { label: string; value: string }) {
    return (
        <div style={{ display: 'flex', gap: 8 }}>
            <span style={{ color: 'var(--text-secondary)', minWidth: 90 }}>{label}</span>
            <span>{value}</span>
        </div>
    );
}

// ── Main Investigate Page ─────────────────────────────────────────────────────
export default function Investigate() {
    const [upn, setUpn] = useState('');
    const [daysBack, setDaysBack] = useState('7');
    const [outputMode, setOutputMode] = useState('both');
    const [options, setOptions] = useState({
        include_cloud: true,
        include_office: true,
        include_audit: true,
        include_identity: true,
        generate_summary: false,
    });
    const [showAdvanced, setShowAdvanced] = useState(false);
    const [jobId, setJobId] = useState<string | null>(null);
    const [job, setJob] = useState<Job | null>(null);
    const [logs, setLogs] = useState<JobUpdate[]>([]);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const feedRef = useRef<HTMLDivElement>(null);
    const wsRef = useRef<WebSocket | null>(null);

    // Poll job status if not using WS
    useEffect(() => {
        if (!jobId) return;
        const poll = setInterval(async () => {
            const j = await getInvestigation(jobId);
            setJob(j);
            if (j.status === 'completed' || j.status === 'failed') clearInterval(poll);
        }, 3000);
        return () => clearInterval(poll);
    }, [jobId]);

    // WebSocket streaming
    useEffect(() => {
        if (!jobId) return;
        const ws = createInvestigationWS(jobId);
        wsRef.current = ws;
        ws.onmessage = (ev) => {
            const update: JobUpdate = JSON.parse(ev.data);
            if (update.phase === 'ping') return;
            setLogs(prev => [...prev, update]);
            setTimeout(() => feedRef.current?.scrollTo({ top: 99999, behavior: 'smooth' }), 50);
        };
        return () => ws.close();
    }, [jobId]);

    const submit = async () => {
        if (!upn.trim()) return;
        setError(null);
        setSubmitting(true);
        setLogs([]);
        setJob(null);
        try {
            const res = await startInvestigation(upn.trim(), parseInt(daysBack), outputMode, options);
            setJobId(res.job_id);
        } catch (e: unknown) {
            setError((e as Error).message ?? 'Failed to start investigation');
        } finally {
            setSubmitting(false);
        }
    };

    const isRunning = job?.status === 'running' || job?.status === 'pending';

    return (
        <div>
            <div className="page-header">
                <div className="page-title">
                    <FontAwesomeIcon icon={faSearch} style={{ marginRight: 12, fontSize: '0.9em', color: 'var(--brand)' }} />
                    Investigate
                </div>
                <div className="page-subtitle">Run a full security investigation for a user account</div>
            </div>

            <div className="page-content">
                <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: 20, alignItems: 'start' }}>
                    {/* ── Config panel ──────────────────────────────── */}
                    <div style={{ position: 'sticky', top: 20 }}>
                        <div className="card">
                            <div className="card-title">
                                <FontAwesomeIcon icon={faScrewdriverWrench} className="card-title-icon" />
                                Investigation Parameters
                            </div>

                            <div className="form-group">
                                <label className="form-label">User Principal Name (UPN)</label>
                                <input
                                    className="form-input mono"
                                    placeholder="user@contoso.com"
                                    value={upn}
                                    onChange={e => setUpn(e.target.value)}
                                    onKeyDown={e => e.key === 'Enter' && submit()}
                                />
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label className="form-label">Look-back Period</label>
                                    <select className="form-select" value={daysBack} onChange={e => setDaysBack(e.target.value)}>
                                        <option value="1">Last 1 day</option>
                                        <option value="7">Last 7 days</option>
                                        <option value="14">Last 14 days</option>
                                        <option value="30">Last 30 days</option>
                                        <option value="90">Last 90 days</option>
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Output Mode</label>
                                    <select className="form-select" value={outputMode} onChange={e => setOutputMode(e.target.value)}>
                                        <option value="inline">Inline Results</option>
                                        <option value="html">HTML Report</option>
                                        <option value="both">Both</option>
                                    </select>
                                </div>
                            </div>

                            <div style={{ marginBottom: 16 }}>
                                <button
                                    className="btn btn-ghost btn-sm"
                                    onClick={() => setShowAdvanced(!showAdvanced)}
                                    style={{ width: '100%', justifyContent: 'space-between', padding: '6px 8px', marginBottom: 8 }}
                                >
                                    <span style={{ fontSize: 11, fontWeight: 700 }}>ADVANCED OPTIONS</span>
                                    <FontAwesomeIcon icon={showAdvanced ? faChevronUp : faChevronDown} fontSize={10} />
                                </button>
                                {showAdvanced && (
                                    <div style={{ padding: '12px', background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}>
                                        <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, cursor: 'pointer' }}>
                                            <input type="checkbox" checked={options.include_cloud} onChange={e => setOptions({ ...options, include_cloud: e.target.checked })} />
                                            Include Cloud App Events (DCA)
                                        </label>
                                        <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, cursor: 'pointer' }}>
                                            <input type="checkbox" checked={options.include_office} onChange={e => setOptions({ ...options, include_office: e.target.checked })} />
                                            Include Office 365 Activity
                                        </label>
                                        <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, cursor: 'pointer' }}>
                                            <input type="checkbox" checked={options.include_audit} onChange={e => setOptions({ ...options, include_audit: e.target.checked })} />
                                            Include Azure AD Audit Logs
                                        </label>
                                        <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, cursor: 'pointer' }}>
                                            <input type="checkbox" checked={options.include_identity} onChange={e => setOptions({ ...options, include_identity: e.target.checked })} />
                                            Include Identity & Device Data
                                        </label>
                                        <hr style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '4px 0' }} />
                                        <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, cursor: 'pointer', color: 'var(--brand)', fontWeight: 600 }}>
                                            <input type="checkbox" checked={options.generate_summary} onChange={e => setOptions({ ...options, generate_summary: e.target.checked })} />
                                            <FontAwesomeIcon icon={faRobot} style={{ fontSize: 11 }} />
                                            Generate AI Executive Summary
                                        </label>
                                    </div>
                                )}
                            </div>

                            {error && (
                                <div style={{ color: 'var(--critical)', fontSize: 12, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                                    <FontAwesomeIcon icon={faTriangleExclamation} />
                                    {error}
                                </div>
                            )}

                            <button
                                className="btn btn-primary"
                                style={{ width: '100%' }}
                                disabled={submitting || isRunning || !upn.trim()}
                                onClick={submit}
                            >
                                {submitting || isRunning
                                    ? <><span className="spinner" /> Investigating…</>
                                    : <><FontAwesomeIcon icon={faRocket} style={{ marginRight: 8 }} /> Start Investigation</>
                                }
                            </button>

                            {job && (
                                <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-secondary)' }}>
                                    Job: <span className="mono">{job.job_id.slice(0, 8)}…</span>
                                    {'  '}
                                    Status: <strong style={{ color: job.status === 'completed' ? 'var(--low)' : job.status === 'failed' ? 'var(--critical)' : 'var(--info)' }}>
                                        {job.status.toUpperCase()}
                                    </strong>
                                </div>
                            )}
                        </div>

                        {/* Tips */}
                        <div className="card" style={{ marginTop: 12 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faLightbulb} className="card-title-icon" style={{ color: 'var(--medium)' }} />
                                Tips
                            </div>
                            <ul style={{ fontSize: 12, color: 'var(--text-secondary)', paddingLeft: 16, lineHeight: 2 }}>
                                <li>7-day look-back is recommended for most investigations</li>
                                <li>HTML mode generates a compact report in the <strong>Reports</strong> tab</li>
                                <li>IP enrichment runs automatically (needs API tokens in .env)</li>
                                <li>Ensure <code>az login</code> is active before starting</li>
                            </ul>
                        </div>
                    </div>

                    {/* ── Live feed + results ───────────────────────── */}
                    <div>
                        {logs.length > 0 && (
                            <div className="card" style={{ marginBottom: 16 }}>
                                <div className="card-title">
                                    <FontAwesomeIcon icon={faTowerBroadcast} className="card-title-icon" />
                                    Investigation Log
                                </div>
                                <div className="progress-feed" ref={feedRef}>
                                    {logs.map((l, i) => (
                                        <div key={i} className={`progress-line phase-${l.phase}`}>
                                            <span style={{ color: 'var(--text-muted)', marginRight: 8 }}>
                                                {l.timestamp.slice(11, 19)}
                                            </span>
                                            {l.message}
                                        </div>
                                    ))}
                                    {isRunning && (
                                        <div className="progress-line" style={{ marginTop: 4 }}>
                                            <span className="spinner" style={{ width: 10, height: 10, borderWidth: 1 }} />
                                            {' '}Running…
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {!jobId && (
                            <div className="empty-state" style={{ marginTop: 48 }}>
                                <div className="empty-state-icon">
                                    <FontAwesomeIcon icon={faSearch} style={{ opacity: 0.3 }} />
                                </div>
                                <div className="empty-state-text" style={{ color: 'var(--text-secondary)' }}>
                                    Enter a UPN and click Start Investigation
                                </div>
                            </div>
                        )}

                        {job?.status === 'failed' && (
                            <div style={{ color: 'var(--critical)', background: 'var(--risk-critical-bg)', border: '1px solid rgba(255,71,71,0.3)', borderRadius: 'var(--radius-md)', padding: 16, fontSize: 13, display: 'flex', alignItems: 'center', gap: 10 }}>
                                <FontAwesomeIcon icon={faCircleXmark} />
                                <span>Investigation failed: {job.error}</span>
                            </div>
                        )}

                        {job?.status === 'completed' && job.result && (
                            <ResultsPanel result={job.result} />
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
