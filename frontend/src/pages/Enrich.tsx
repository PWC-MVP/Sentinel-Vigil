import { useState, useEffect } from 'react';
import { startEnrichment, getEnrichment, type IPIntelligence } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faGlobe,
    faSearch,
    faRocket,
    faLightbulb,
    faCheck,
    faTowerBroadcast,
    faDownload,
    faLocationDot,
    faBuilding,
    faLink,
    faTriangleExclamation,
    faFilePdf,
    faFileCode
} from '@fortawesome/free-solid-svg-icons';

function FlagBadge({ label, cls }: { label: string; cls: string }) {
    return <span className={`badge ${cls}`}>{label}</span>;
}

function IPDetailCard({ ip }: { ip: IPIntelligence }) {
    const cardClass = ip.threat_detected ? 'threat' : ip.anomaly_type ? 'anomaly' : '';
    return (
        <div className={`ip-card ${cardClass}`} style={{ minWidth: 260 }}>
            <div className="ip-addr">{ip.ip}</div>
            <div className="ip-meta">
                <FontAwesomeIcon icon={faLocationDot} style={{ marginRight: 6, fontSize: 10, opacity: 0.7 }} />
                {[ip.city, ip.region, ip.country].filter(Boolean).join(', ') || 'Unknown location'}<br />
                <FontAwesomeIcon icon={faBuilding} style={{ marginRight: 6, fontSize: 10, opacity: 0.7 }} />
                {ip.org || 'Unknown organization'}<br />
                <FontAwesomeIcon icon={faLink} style={{ marginRight: 6, fontSize: 10, opacity: 0.7 }} />
                {ip.asn || 'Unknown ASN'}
            </div>
            <div className="ip-flags" style={{ marginBottom: ip.threat_detected ? 8 : 0 }}>
                {ip.is_vpn && <FlagBadge label="VPN" cls="badge-muted" />}
                {ip.is_tor && <FlagBadge label="TOR" cls="badge-high" />}
                {ip.is_proxy && <FlagBadge label="PROXY" cls="badge-muted" />}
                {ip.threat_detected && <FlagBadge label="THREAT" cls="badge-critical" />}
                {(ip.abuse_confidence_score ?? 0) > 0 && (
                    <FlagBadge label={`ABUSE ${ip.abuse_confidence_score}%`} cls={
                        (ip.abuse_confidence_score ?? 0) > 50 ? 'badge-high' : 'badge-medium'
                    } />
                )}
                {(ip.total_reports ?? 0) > 0 && (
                    <FlagBadge label={`${ip.total_reports} reports`} cls="badge-muted" />
                )}
            </div>
            {ip.threat_description && (
                <div style={{ fontSize: 11, color: 'var(--critical)', marginTop: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <FontAwesomeIcon icon={faTriangleExclamation} />
                    {ip.threat_description}
                </div>
            )}
        </div>
    );
}

export default function Enrich() {
    const [ipInput, setIpInput] = useState('');
    const [jobId, setJobId] = useState<string | null>(null);
    const [status, setStatus] = useState<'idle' | 'running' | 'done' | 'error'>('idle');
    const [results, setResults] = useState<IPIntelligence[]>([]);
    const [logs, setLogs] = useState<string[]>([]);
    const [error, setError] = useState<string | null>(null);

    // Poll enrichment status
    useEffect(() => {
        if (!jobId || status !== 'running') return;
        const poll = setInterval(async () => {
            const data = await getEnrichment(jobId);
            if (data.updates) setLogs(data.updates.map((u: { message: string }) => u.message));
            if (data.status === 'completed') {
                setResults(data.results || []);
                setStatus('done');
                clearInterval(poll);
            } else if (data.status === 'failed') {
                setError(data.error || 'Enrichment failed');
                setStatus('error');
                clearInterval(poll);
            }
        }, 1500);
        return () => clearInterval(poll);
    }, [jobId, status]);

    const submit = async () => {
        const ips = ipInput.split(/[\s,\n]+/).map(s => s.trim()).filter(Boolean);
        if (!ips.length) return;
        setError(null);
        setResults([]);
        setLogs([]);
        setStatus('running');
        try {
            const res = await startEnrichment(ips);
            setJobId(res.job_id);
        } catch (e: unknown) {
            setError((e as Error).message);
            setStatus('error');
        }
    };

    const handleExport = async (type: 'pdf' | 'html') => {
        try {
            const endpoint = type === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const html = `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>IP Enrichment Report</title>
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 40px; color: #333; max-width: 1000px; margin: 0 auto; line-height: 1.6; }
                        h1 { color: #D04A02; border-bottom: 3px solid #D04A02; padding-bottom: 12px; margin-bottom: 30px; }
                        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
                        .ip-card { border: 1px solid #e5e5e5; border-radius: 12px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
                        .threat { border-left: 5px solid #C0392B; background: #FFF5F5; }
                        .anomaly { border-left: 5px solid #E67E22; background: #FFF9F2; }
                        .ip-addr { font-size: 20px; font-weight: 800; margin-bottom: 10px; font-family: monospace; }
                        .meta { font-size: 13px; color: #666; margin-bottom: 15px; }
                        .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; margin-right: 6px; background: #f0f0f0; color: #444; }
                        .badge-critical { background: #fee; color: #c00; border: 1px solid rgba(200,0,0,0.1); }
                        .badge-high { background: #fff1e0; color: #e67e22; border: 1px solid rgba(230,126,34,0.1); }
                        .footer { margin-top: 50px; font-size: 12px; color: #888; border-top: 1px solid #eee; padding-top: 20px; }
                    </style>
                </head>
                <body>
                    <h1>ARIA IP Enrichment Report</h1>
                    <p style="margin-bottom: 30px;">Generated on ${new Date().toLocaleString()}</p>
                    <div class="grid">
                        ${results.map(r => `
                            <div class="ip-card ${r.threat_detected ? 'threat' : r.anomaly_type ? 'anomaly' : ''}">
                                <div class="ip-addr">${r.ip}</div>
                                <div class="meta">
                                    <strong>Geo:</strong> ${[r.city, r.region, r.country].filter(Boolean).join(', ') || 'Unknown'}<br/>
                                    <strong>Org:</strong> ${r.org || 'Unknown'}<br/>
                                    <strong>ASN:</strong> ${r.asn || 'Unknown'}
                                </div>
                                <div class="flags">
                                    ${r.threat_detected ? '<span class="badge badge-critical">THREAT DETECTED</span>' : ''}
                                    ${r.is_vpn ? '<span class="badge">VPN</span>' : ''}
                                    ${r.is_tor ? '<span class="badge badge-high">TOR EXIT</span>' : ''}
                                    ${r.abuse_confidence_score ? `<span class="badge">ABUSE: ${r.abuse_confidence_score}%</span>` : ''}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                    <div class="footer">
                        Sentinel Vigil ARIA · Confidential Analysis
                    </div>
                </body>
                </html>
            `;

            const resp = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    html,
                    filename: `IP_Enrichment_${new Date().toISOString().slice(0, 10)}.${type}`
                })
            });

            if (!resp.ok) throw new Error(`${type.toUpperCase()} export failed`);
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = `IP_Enrichment_${new Date().toISOString().slice(0, 10)}.${type}`; a.click();
        } catch (e) {
            console.error(e);
            alert(`Failed to export ${type.toUpperCase()}`);
        }
    };

    return (
        <div>
            <div className="page-header">
                <div className="page-title">
                    <FontAwesomeIcon icon={faGlobe} style={{ marginRight: 12, fontSize: '0.9em', color: 'var(--brand)' }} />
                    IP Enrichment
                </div>
                <div className="page-subtitle">Enrich IP addresses using ipinfo.io, AbuseIPDB, vpnapi.io, and Shodan</div>
            </div>

            <div className="page-content">
                <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: 20, alignItems: 'start' }}>
                    {/* ── Input panel ─────────────────────────────── */}
                    <div>
                        <div className="card">
                            <div className="card-title">
                                <FontAwesomeIcon icon={faSearch} className="card-title-icon" />
                                Enter IPs to Enrich
                            </div>
                            <div className="form-group">
                                <label className="form-label">IP Addresses (one per line or comma-separated)</label>
                                <textarea
                                    className="form-textarea"
                                    placeholder={"1.2.3.4\n5.6.7.8\n..."}
                                    value={ipInput}
                                    onChange={e => setIpInput(e.target.value)}
                                    rows={8}
                                />
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
                                disabled={status === 'running' || !ipInput.trim()}
                                onClick={submit}
                            >
                                {status === 'running'
                                    ? <><span className="spinner" /> Enriching…</>
                                    : <><FontAwesomeIcon icon={faRocket} style={{ marginRight: 8 }} /> Enrich IPs</>}
                            </button>
                        </div>

                        <div className="card" style={{ marginTop: 12 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faLightbulb} className="card-title-icon" style={{ color: 'var(--medium)' }} />
                                Sources
                            </div>
                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 2 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                    <FontAwesomeIcon icon={faCheck} style={{ fontSize: 10, color: 'var(--brand)' }} />
                                    <span><strong>ipinfo.io</strong> — Geo, ASN, org, VPN</span>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                    <FontAwesomeIcon icon={faCheck} style={{ fontSize: 10, color: 'var(--brand)' }} />
                                    <span><strong>vpnapi.io</strong> — VPN / Proxy / Tor</span>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                    <FontAwesomeIcon icon={faCheck} style={{ fontSize: 10, color: 'var(--brand)' }} />
                                    <span><strong>AbuseIPDB</strong> — Abuse score + reports</span>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                    <FontAwesomeIcon icon={faCheck} style={{ fontSize: 10, color: 'var(--brand)' }} />
                                    <span><strong>Shodan</strong> — Open ports + CVEs</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* ── Results ─────────────────────────────────── */}
                    <div>
                        {logs.length > 0 && (
                            <div className="card" style={{ marginBottom: 16 }}>
                                <div className="card-title">
                                    <FontAwesomeIcon icon={faTowerBroadcast} className="card-title-icon" />
                                    Enrichment Log
                                </div>
                                <div className="progress-feed" style={{ maxHeight: 140 }}>
                                    {logs.map((l, i) => <div key={i} className="progress-line">{l}</div>)}
                                </div>
                            </div>
                        )}

                        {status === 'done' && results.length > 0 && (
                            <>
                                <div style={{ marginBottom: 14, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 10 }}>
                                        <span>Enriched {results.length} IP{results.length !== 1 ? 's' : ''}</span>
                                        {results.filter(r => r.threat_detected).length > 0 && (
                                            <span className="badge badge-critical">
                                                {results.filter(r => r.threat_detected).length} Threats
                                            </span>
                                        )}
                                        {results.filter(r => r.is_vpn || r.is_tor).length > 0 && (
                                            <span className="badge badge-muted">
                                                {results.filter(r => r.is_vpn || r.is_tor).length} VPN/Tor
                                            </span>
                                        )}
                                    </div>
                                    <div style={{ display: 'flex', gap: 8 }}>
                                        <button className="btn btn-secondary btn-sm" onClick={() => handleExport('pdf')}>
                                            <FontAwesomeIcon icon={faFilePdf} style={{ marginRight: 6 }} /> PDF
                                        </button>
                                        <button className="btn btn-secondary btn-sm" onClick={() => handleExport('html')}>
                                            <FontAwesomeIcon icon={faFileCode} style={{ marginRight: 6 }} /> HTML
                                        </button>
                                        <button
                                            className="btn btn-secondary btn-sm"
                                            onClick={() => {
                                                const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
                                                const url = URL.createObjectURL(blob);
                                                const a = document.createElement('a'); a.href = url; a.download = 'ip_enrichment.json'; a.click();
                                            }}
                                        >
                                            <FontAwesomeIcon icon={faDownload} style={{ marginRight: 6 }} />
                                            JSON
                                        </button>
                                    </div>
                                </div>
                                <div className="ip-grid">
                                    {results.map(ip => <IPDetailCard key={ip.ip} ip={ip} />)}
                                </div>
                            </>
                        )}

                        {status === 'idle' && (
                            <div className="empty-state" style={{ marginTop: 60 }}>
                                <div className="empty-state-icon">
                                    <FontAwesomeIcon icon={faGlobe} style={{ opacity: 0.3 }} />
                                </div>
                                <div className="empty-state-text">Enter IP addresses to begin enrichment</div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
