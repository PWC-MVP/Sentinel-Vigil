import { useState, useEffect, useRef } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faXmark, faCircleCheck, faSpinner, faTriangleExclamation,
    faDownload, faBug, faShieldHalved, faSearch, faFileLines,
    faChevronDown, faChevronRight, faCircleDot,
} from '@fortawesome/free-solid-svg-icons';

interface Article {
    id: string;
    title: string;
    summary: string;
    link: string;
    source: string;
    published: string;
    tags: string[];
    category: string;
}

interface MitreTechnique {
    id: string;
    name: string;
    tactic: string;
}

interface IOCs {
    ips: string[];
    domains: string[];
    hashes: string[];
    cves: string[];
}

interface KqlQueryMeta {
    title: string;
    description: string;
    severity: string;
}

interface KqlResult {
    index: number;
    title: string;
    description: string;
    severity: string;
    query: string;
    row_count: number;
    columns: string[];
    rows: Record<string, unknown>[];
    status: 'running' | 'retrying' | 'success' | 'error';
    error?: string;
    retryAttempt?: number;
    attempts?: number;
}

interface AnalysisData {
    threat_summary: string;
    threat_actor: string;
    targeted_sectors: string[];
    affected_systems: string[];
    iocs: IOCs;
    mitre_techniques: MitreTechnique[];
    risk_level: string;
    category?: string;
    kql_queries: KqlQueryMeta[];
}

type StepId = 'fetch' | 'analyze' | 'kql' | 'report';
type StepStatus = 'pending' | 'running' | 'done' | 'error';

interface Props {
    article: Article;
    onClose: () => void;
}

const RISK_COLORS: Record<string, { color: string; bg: string; border: string }> = {
    Critical: { color: '#E74C3C', bg: '#E74C3C18', border: '#E74C3C50' },
    High:     { color: '#E67E22', bg: '#E67E2218', border: '#E67E2250' },
    Medium:   { color: '#F39C12', bg: '#F39C1218', border: '#F39C1250' },
    Low:      { color: '#2ECC71', bg: '#2ECC7118', border: '#2ECC7150' },
};

const SEV_COLORS: Record<string, string> = {
    High: '#E74C3C', Medium: '#F39C12', Low: '#2ECC71',
};

function StepRow({ label, status, msg }: { id?: StepId; label: string; status: StepStatus; msg?: string }) {
    return (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border-color)' }}>
            <div style={{ width: 18, flexShrink: 0, paddingTop: 1 }}>
                {status === 'done'    && <FontAwesomeIcon icon={faCircleCheck} style={{ color: '#2ECC71', fontSize: 14 }} />}
                {status === 'running' && <FontAwesomeIcon icon={faSpinner} spin style={{ color: 'var(--brand)', fontSize: 14 }} />}
                {status === 'error'   && <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: '#E74C3C', fontSize: 14 }} />}
                {status === 'pending' && <FontAwesomeIcon icon={faCircleDot} style={{ color: 'var(--text-muted)', fontSize: 14 }} />}
            </div>
            <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: status === 'pending' ? 'var(--text-muted)' : 'var(--text-primary)' }}>{label}</div>
                {msg && status === 'running' && (
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{msg}</div>
                )}
            </div>
        </div>
    );
}

function KqlCard({ result, expanded, onToggle }: { result: KqlResult; expanded: boolean; onToggle: () => void }) {
    const sevColor = SEV_COLORS[result.severity] || '#7F8C8D';
    return (
        <div style={{ border: '1px solid var(--border-color)', borderRadius: 8, overflow: 'hidden', marginBottom: 6 }}>
            <button
                onClick={onToggle}
                style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: 'var(--bg-higher)', border: 'none', cursor: 'pointer', textAlign: 'left' }}
            >
                <div style={{ flexShrink: 0 }}>
                    {(result.status === 'running' || result.status === 'retrying') && <FontAwesomeIcon icon={faSpinner} spin style={{ color: result.status === 'retrying' ? '#F39C12' : 'var(--brand)', fontSize: 11 }} />}
                    {result.status === 'success' && result.row_count > 0 && <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: '#E67E22', fontSize: 11 }} />}
                    {result.status === 'success' && result.row_count === 0 && <FontAwesomeIcon icon={faCircleCheck} style={{ color: '#2ECC71', fontSize: 11 }} />}
                    {result.status === 'error'   && <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: '#E74C3C', fontSize: 11 }} />}
                </div>
                <div style={{ flex: 1, fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' }}>{result.title}</div>
                <span style={{ fontSize: 9, fontWeight: 700, color: sevColor, background: `${sevColor}18`, padding: '1px 7px', borderRadius: 10 }}>{result.severity}</span>
                {result.status === 'retrying' && (
                    <span style={{ fontSize: 9, fontWeight: 700, color: '#F39C12', background: '#F39C1218', padding: '1px 7px', borderRadius: 10, whiteSpace: 'nowrap' }}>
                        ↻ AI fixing (attempt {result.retryAttempt})
                    </span>
                )}
                {result.status === 'success' && (
                    <span style={{ fontSize: 10, fontWeight: 700, color: result.row_count > 0 ? '#E67E22' : '#2ECC71', marginLeft: 4, whiteSpace: 'nowrap' }}>
                        {result.row_count > 0 ? `⚠ ${result.row_count} hits` : '✓ Clean'}
                    </span>
                )}
                {result.status === 'success' && result.attempts && result.attempts > 1 && (
                    <span style={{ fontSize: 9, color: '#2ECC71', background: '#2ECC7115', padding: '1px 7px', borderRadius: 10, whiteSpace: 'nowrap' }}>
                        fixed in {result.attempts} attempts
                    </span>
                )}
                {result.status === 'error' && (
                    <span style={{ fontSize: 10, color: '#E74C3C', marginLeft: 4 }}>Failed</span>
                )}
                <FontAwesomeIcon icon={expanded ? faChevronDown : faChevronRight} style={{ fontSize: 9, color: 'var(--text-muted)', marginLeft: 4 }} />
            </button>

            {expanded && (
                <div style={{ padding: '10px 12px', background: 'var(--bg-card)' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>{result.description}</div>
                    <pre style={{ margin: '0 0 8px', padding: '8px 10px', background: 'var(--bg-base)', borderRadius: 6, fontSize: 10, fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#a5d6ff', lineHeight: 1.6, maxHeight: 160, overflowY: 'auto' }}>
                        {result.query}
                    </pre>
                    {result.status === 'error' && (
                        <div style={{ fontSize: 11, color: '#E74C3C', padding: '6px 8px', background: '#E74C3C10', borderRadius: 4 }}>
                            {result.error}
                        </div>
                    )}
                    {result.status === 'success' && result.rows.length > 0 && (
                        <div style={{ overflowX: 'auto', maxHeight: 180, overflowY: 'auto' }}>
                            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                                <thead>
                                    <tr>{result.columns.slice(0, 6).map(c => (
                                        <th key={c} style={{ padding: '4px 8px', background: 'var(--bg-higher)', color: 'var(--text-muted)', fontWeight: 700, textAlign: 'left', borderBottom: '1px solid var(--border-color)', whiteSpace: 'nowrap' }}>{c}</th>
                                    ))}</tr>
                                </thead>
                                <tbody>
                                    {result.rows.slice(0, 10).map((row, i) => (
                                        <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                                            {result.columns.slice(0, 6).map(c => (
                                                <td key={c} style={{ padding: '4px 8px', color: 'var(--text-secondary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                    {String(row[c] ?? '—').slice(0, 80)}
                                                </td>
                                            ))}
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                    {result.status === 'success' && result.row_count === 0 && (
                        <div style={{ fontSize: 11, color: '#2ECC71', padding: '6px 8px', background: '#2ECC7110', borderRadius: 4 }}>
                            No matching records — workspace appears clean for this indicator.
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default function ThreatInvestigatePanel({ article, onClose }: Props) {
    const [steps, setSteps] = useState<Record<StepId, StepStatus>>({
        fetch: 'running', analyze: 'pending', kql: 'pending', report: 'pending',
    });
    const [statusMsg, setStatusMsg] = useState('Fetching article content…');
    const [analysis, setAnalysis] = useState<AnalysisData | null>(null);
    const [kqlResults, setKqlResults] = useState<KqlResult[]>([]);
    const [expandedKql, setExpandedKql] = useState<Record<number, boolean>>({});
    const [reportChunks, setReportChunks] = useState('');
    const [reportHtml, setReportHtml] = useState('');
    const [done, setDone] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [totalHits, setTotalHits] = useState(0);
    const abortRef = useRef<AbortController | null>(null);
    const reportRef = useRef<HTMLIFrameElement>(null);

    useEffect(() => {
        const ctrl = new AbortController();
        abortRef.current = ctrl;

        (async () => {
            try {
                const res = await fetch('/api/threat-feed/investigate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        title: article.title,
                        link: article.link,
                        summary: article.summary,
                        source: article.source,
                        category: article.category,
                    }),
                    signal: ctrl.signal,
                });

                if (!res.ok) throw new Error(`Server error ${res.status}`);
                const reader = res.body!.getReader();
                const decoder = new TextDecoder();
                let buffer = '';

                while (true) {
                    const { done: streamDone, value } = await reader.read();
                    if (streamDone) break;
                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split('\n');
                    buffer = lines.pop() ?? '';

                    for (const line of lines) {
                        if (!line.startsWith('data: ')) continue;
                        try {
                            const event = JSON.parse(line.slice(6));
                            handleEvent(event);
                        } catch { /* ignore malformed */ }
                    }
                }
            } catch (e: unknown) {
                if ((e as Error).name !== 'AbortError') {
                    setError((e as Error).message || 'Investigation failed');
                    setSteps(s => ({ ...s, fetch: 'error' }));
                }
            }
        })();

        return () => ctrl.abort();
    }, []);

    // Update iframe when reportHtml is finalised
    useEffect(() => {
        if (reportHtml && reportRef.current) {
            reportRef.current.srcdoc = reportHtml;
        }
    }, [reportHtml]);

    function handleEvent(event: Record<string, unknown>) {
        const type = event.type as string;

        if (type === 'status') {
            const msg = event.msg as string;
            setStatusMsg(msg);
            const step = event.step as string;
            if (step === 'fetch')      setSteps(s => ({ ...s, fetch: 'running' }));
            if (step === 'fetch_done') setSteps(s => ({ ...s, fetch: 'done', analyze: 'running' }));
            if (step === 'analyze')    setSteps(s => ({ ...s, analyze: 'running' }));
            if (step === 'kql')        setSteps(s => ({ ...s, analyze: 'done', kql: 'running' }));
            if (step === 'report')     setSteps(s => ({ ...s, kql: 'done', report: 'running' }));
        }

        if (type === 'analysis') {
            setAnalysis(event as unknown as AnalysisData);
            // Pre-populate kqlResults with running placeholders
            const queries = (event.kql_queries as KqlQueryMeta[]) || [];
            setKqlResults(queries.map((q, i) => ({
                index: i, title: q.title, description: q.description,
                severity: q.severity, query: '', row_count: 0,
                columns: [], rows: [], status: 'running',
            })));
        }

        if (type === 'kql_running') {
            const idx = event.index as number;
            const query = event.query as string;
            const attempt = (event.attempt as number) ?? 0;
            setKqlResults(prev => prev.map(r =>
                r.index === idx ? { ...r, query, status: attempt > 0 ? 'retrying' : 'running', retryAttempt: attempt } : r
            ));
        }

        if (type === 'kql_retrying') {
            const idx = event.index as number;
            const attempt = event.attempt as number;
            setKqlResults(prev => prev.map(r =>
                r.index === idx ? { ...r, status: 'retrying', retryAttempt: attempt, error: event.error as string } : r
            ));
        }

        if (type === 'kql_result') {
            const idx = event.index as number;
            setKqlResults(prev => prev.map(r => {
                if (r.index !== idx) return r;
                if (event.status === 'success') {
                    return { ...r, status: 'success', row_count: event.row_count as number, attempts: event.attempts as number };
                }
                return { ...r, status: 'error', error: event.error as string, attempts: event.attempts as number };
            }));
        }

        if (type === 'report_chunk') {
            setReportChunks(prev => prev + (event.text as string));
        }

        if (type === 'done') {
            setSteps(s => ({ ...s, report: 'done' }));
            setReportHtml(event.report_html as string);
            setTotalHits(event.total_hits as number);
            setDone(true);
        }

        if (type === 'error') {
            setError(event.msg as string);
            setSteps(s => {
                const next = { ...s };
                (Object.keys(next) as StepId[]).forEach(k => { if (next[k] === 'running') next[k] = 'error'; });
                return next;
            });
        }
    }

    const exportHtml = () => {
        const html = reportHtml || reportChunks;
        if (!html) return;
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Threat_Investigation_${article.title.slice(0, 40).replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().slice(0, 10)}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const riskStyle = RISK_COLORS[analysis?.risk_level ?? ''] ?? RISK_COLORS.Medium;
    const stepLabels: Record<StepId, string> = {
        fetch:   'Fetch article content',
        analyze: 'AI threat analysis & KQL generation',
        kql:     `Run detection queries (${kqlResults.length})`,
        report:  'Generate investigation report',
    };

    return (
        <div style={{ position: 'fixed', inset: 0, zIndex: 2000, background: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'stretch' }}>
            <div style={{ display: 'flex', flexDirection: 'column', width: '100%', background: 'var(--bg-base)', overflow: 'hidden' }}>

                {/* ── Header ─────────────────────────────────────────────── */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 20px', background: 'var(--bg-card)', borderBottom: '1px solid var(--border-color)', flexShrink: 0 }}>
                    <FontAwesomeIcon icon={faSearch} style={{ color: 'var(--brand)', fontSize: 16 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 11, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--brand)' }}>ARIA Threat Investigation</div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{article.title}</div>
                    </div>
                    <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--brand)', background: 'var(--pwc-orange-light)', padding: '3px 10px', borderRadius: 6, flexShrink: 0 }}>
                        {article.source}
                    </span>
                    {done && (
                        <button className="btn btn-primary" onClick={exportHtml} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, flexShrink: 0 }}>
                            <FontAwesomeIcon icon={faDownload} />
                            Export HTML
                        </button>
                    )}
                    <button className="btn btn-ghost" onClick={() => { abortRef.current?.abort(); onClose(); }} style={{ flexShrink: 0 }}>
                        <FontAwesomeIcon icon={faXmark} />
                    </button>
                </div>

                {/* ── Body ───────────────────────────────────────────────── */}
                <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

                    {/* Left panel */}
                    <div style={{ width: 320, flexShrink: 0, borderRight: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                        <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px' }}>

                            {/* Progress steps */}
                            <div style={{ fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 8 }}>Progress</div>
                            {(Object.keys(steps) as StepId[]).map(id => (
                                <StepRow key={id} id={id} label={stepLabels[id]} status={steps[id]}
                                    msg={steps[id] === 'running' ? statusMsg : undefined} />
                            ))}

                            {error && (
                                <div style={{ marginTop: 10, padding: '8px 10px', background: '#E74C3C10', border: '1px solid #E74C3C40', borderRadius: 6, fontSize: 11, color: '#E74C3C' }}>
                                    <FontAwesomeIcon icon={faTriangleExclamation} style={{ marginRight: 6 }} />
                                    {error}
                                </div>
                            )}

                            {/* Threat Intel */}
                            {analysis && (
                                <div style={{ marginTop: 16 }}>
                                    <div style={{ fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 8 }}>Threat Intelligence</div>

                                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                                        <span style={{ fontSize: 10, fontWeight: 800, color: riskStyle.color, background: riskStyle.bg, border: `1px solid ${riskStyle.border}`, padding: '2px 10px', borderRadius: 20 }}>
                                            {analysis.risk_level} Risk
                                        </span>
                                        <span style={{ fontSize: 10, color: 'var(--text-muted)', padding: '2px 8px', background: 'var(--bg-higher)', borderRadius: 10 }}>
                                            {analysis.category ?? article.category}
                                        </span>
                                    </div>

                                    {analysis.threat_summary && (
                                        <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 10, padding: '8px 10px', background: 'var(--bg-card)', borderRadius: 6, border: '1px solid var(--border-color)' }}>
                                            {analysis.threat_summary}
                                        </div>
                                    )}

                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 10 }}>
                                        {analysis.threat_actor !== 'Unknown' && (
                                            <div style={{ fontSize: 11 }}>
                                                <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Actor: </span>
                                                <span style={{ color: '#E74C3C', fontWeight: 700 }}>{analysis.threat_actor}</span>
                                            </div>
                                        )}
                                        {analysis.targeted_sectors.length > 0 && (
                                            <div style={{ fontSize: 11 }}>
                                                <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Targets: </span>
                                                <span style={{ color: 'var(--text-secondary)' }}>{analysis.targeted_sectors.join(', ')}</span>
                                            </div>
                                        )}
                                    </div>

                                    {/* IOCs */}
                                    {Object.values(analysis.iocs).some(v => v.length > 0) && (
                                        <div style={{ marginBottom: 10 }}>
                                            <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>IOCs</div>
                                            {analysis.iocs.ips.map(ip => (
                                                <div key={ip} style={{ fontSize: 10, fontFamily: 'monospace', color: '#E74C3C', padding: '1px 0' }}>IP: {ip}</div>
                                            ))}
                                            {analysis.iocs.domains.map(d => (
                                                <div key={d} style={{ fontSize: 10, fontFamily: 'monospace', color: '#E67E22', padding: '1px 0', wordBreak: 'break-all' }}>Domain: {d}</div>
                                            ))}
                                            {analysis.iocs.cves.map(c => (
                                                <div key={c} style={{ fontSize: 10, fontFamily: 'monospace', color: '#9B59B6', padding: '1px 0' }}>CVE: {c}</div>
                                            ))}
                                            {analysis.iocs.hashes.map(h => (
                                                <div key={h} style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-muted)', padding: '1px 0', wordBreak: 'break-all' }}>Hash: {h.slice(0, 32)}…</div>
                                            ))}
                                        </div>
                                    )}

                                    {/* MITRE */}
                                    {analysis.mitre_techniques.length > 0 && (
                                        <div style={{ marginBottom: 10 }}>
                                            <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                                                <FontAwesomeIcon icon={faShieldHalved} style={{ marginRight: 4 }} />MITRE ATT&amp;CK
                                            </div>
                                            {analysis.mitre_techniques.map(t => (
                                                <div key={t.id} style={{ display: 'flex', gap: 6, alignItems: 'center', padding: '2px 0' }}>
                                                    <code style={{ fontSize: 9, fontWeight: 700, color: 'var(--brand)', background: 'var(--pwc-orange-light)', padding: '1px 6px', borderRadius: 4 }}>{t.id}</code>
                                                    <span style={{ fontSize: 10, color: 'var(--text-secondary)' }}>{t.name}</span>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* KQL results */}
                            {kqlResults.length > 0 && (
                                <div style={{ marginTop: 10 }}>
                                    <div style={{ fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 8 }}>
                                        <FontAwesomeIcon icon={faBug} style={{ marginRight: 4 }} />
                                        Detection Queries
                                        {done && totalHits > 0 && (
                                            <span style={{ marginLeft: 6, color: '#E67E22' }}>{totalHits} hit{totalHits !== 1 ? 's' : ''}</span>
                                        )}
                                    </div>
                                    {kqlResults.map(r => (
                                        <KqlCard
                                            key={r.index}
                                            result={r}
                                            expanded={!!expandedKql[r.index]}
                                            onToggle={() => setExpandedKql(prev => ({ ...prev, [r.index]: !prev[r.index] }))}
                                        />
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Right panel — Report */}
                    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                        <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
                            <FontAwesomeIcon icon={faFileLines} style={{ color: 'var(--brand)', fontSize: 14 }} />
                            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>Investigation Report</span>
                            {!done && steps.report === 'running' && (
                                <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
                                    <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 11 }} />
                                    Generating…
                                </span>
                            )}
                            {done && (
                                <>
                                    <span style={{ fontSize: 11, color: '#2ECC71', fontWeight: 600 }}>
                                        <FontAwesomeIcon icon={faCircleCheck} style={{ marginRight: 4 }} />
                                        Complete
                                    </span>
                                    <button className="btn btn-primary btn-sm" onClick={exportHtml} style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
                                        <FontAwesomeIcon icon={faDownload} />
                                        Export HTML
                                    </button>
                                </>
                            )}
                        </div>

                        <div style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
                            {/* Show live text stream while generating */}
                            {!done && (
                                <div style={{ height: '100%', overflowY: 'auto', padding: 20 }}>
                                    {!reportChunks && !error && (
                                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 16 }}>
                                            <div className="spinner spinner-lg" />
                                            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>{statusMsg}</div>
                                        </div>
                                    )}
                                    {reportChunks && (
                                        <pre style={{ margin: 0, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                            {reportChunks}
                                            <span style={{ display: 'inline-block', width: 8, height: 14, background: 'var(--brand)', marginLeft: 2, animation: 'blink 1s step-end infinite', verticalAlign: 'middle' }} />
                                        </pre>
                                    )}
                                </div>
                            )}

                            {/* Show rendered HTML when done */}
                            {done && reportHtml && (
                                <iframe
                                    ref={reportRef}
                                    style={{ width: '100%', height: '100%', border: 'none' }}
                                    title="Threat Investigation Report"
                                    sandbox="allow-same-origin"
                                />
                            )}

                            {error && !reportChunks && (
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                                    <div style={{ textAlign: 'center', padding: 40 }}>
                                        <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: '#E74C3C', fontSize: 40, marginBottom: 16 }} />
                                        <div style={{ fontSize: 14, color: 'var(--text-secondary)', maxWidth: 400 }}>{error}</div>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            <style>{`
                @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
            `}</style>
        </div>
    );
}
