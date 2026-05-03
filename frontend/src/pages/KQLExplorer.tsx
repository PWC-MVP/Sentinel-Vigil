import { useState, useRef } from 'react';
import { http as axios, runKQL, type KQLResult } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faBolt, faWandMagicSparkles, faPlay, faFileCode, faTable,
    faSpinner, faLightbulb, faXmark, faCopy, faCheck,
    faCircleInfo, faTriangleExclamation,
} from '@fortawesome/free-solid-svg-icons';

const EXAMPLE_PROMPTS = [
    'Failed sign-ins from unusual countries in the last 7 days',
    'High severity security alerts in the last 24 hours',
    'Users with multiple failed MFA attempts',
    'Privileged role assignments and changes',
    'Suspicious PowerShell execution on endpoints',
    'DLP policy violations in the last 7 days',
    'Impossible travel sign-ins detected',
    'Azure resource deletions in the last 30 days',
    'Active security incidents by severity',
    'Malware detections by Microsoft Defender',
    'Anomalous sign-in locations for a specific user',
    'Cloud app events with admin privileges',
];

export default function KQLExplorer() {
    const [prompt, setPrompt]           = useState('');
    const [days, setDays]               = useState('30');
    const [generating, setGenerating]   = useState(false);
    const [genError, setGenError]       = useState<string | null>(null);

    const [query, setQuery]             = useState('');
    const [explanation, setExplanation] = useState('');
    const [queryReady, setQueryReady]   = useState(false);
    const [copied, setCopied]           = useState(false);

    const [running, setRunning]         = useState(false);
    const [result, setResult]           = useState<KQLResult | null>(null);
    const [runError, setRunError]       = useState<string | null>(null);
    const [elapsed, setElapsed]         = useState<number | null>(null);

    const queryRef = useRef<HTMLTextAreaElement>(null);

    const generateQuery = async () => {
        if (!prompt.trim()) return;
        setGenerating(true);
        setGenError(null);
        setQueryReady(false);
        setResult(null);
        setRunError(null);
        try {
            const res = await axios.post('/api/kql/generate', { prompt: prompt.trim(), days: parseInt(days) });
            setQuery(res.data.query);
            setExplanation(res.data.explanation || '');
            setQueryReady(true);
            setTimeout(() => queryRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
        } catch (e: unknown) {
            const err = e as { response?: { data?: { detail?: string } }; message?: string };
            setGenError(err?.response?.data?.detail ?? err?.message ?? 'Generation failed');
        } finally {
            setGenerating(false);
        }
    };

    const runQuery = async () => {
        if (!query.trim()) return;
        setRunning(true);
        setRunError(null);
        setResult(null);
        const start = Date.now();
        try {
            const res = await runKQL(query, parseInt(days));
            setResult(res);
            setElapsed(Date.now() - start);
        } catch (e: unknown) {
            const err = e as { response?: { data?: { detail?: string } }; message?: string };
            setRunError(err?.response?.data?.detail ?? err?.message ?? 'Query failed');
        } finally {
            setRunning(false);
        }
    };

    const copyQuery = () => {
        navigator.clipboard.writeText(query);
        setCopied(true);
        setTimeout(() => setCopied(false), 1600);
    };

    const exportHTML = () => {
        if (!result) return;
        const dateStr = new Date().toLocaleString();
        const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const rows = result.rows.map(r =>
            `<tr>${result.columns.map(c => `<td>${esc(String(r[c] ?? ''))}</td>`).join('')}</tr>`
        ).join('');
        const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"><title>KQL Results</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:40px;color:#1e293b;background:#f8fafc;margin:0}
  h1{color:#D04A02;border-bottom:3px solid #D04A02;padding-bottom:10px;font-size:22px;margin-bottom:6px}
  .meta{font-size:12px;color:#64748b;margin:0 0 16px}
  .intent{background:#fff7ed;border:1px solid #fed7aa;padding:10px 14px;border-radius:8px;font-size:13px;color:#92400e;margin-bottom:14px}
  .intent strong{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;color:#b45309}
  .query-box{background:#f1f5f9;border:1px solid #e2e8f0;padding:14px 16px;border-radius:8px;font-family:"JetBrains Mono",Consolas,monospace;font-size:12px;white-space:pre-wrap;color:#0f172a;margin-bottom:20px;line-height:1.6}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:4px}
  th{background:#f1f5f9;text-align:left;padding:9px 12px;border:1px solid #e2e8f0;font-weight:700;color:#475569;text-transform:uppercase;font-size:10px;letter-spacing:.04em}
  td{padding:8px 12px;border:1px solid #e2e8f0;word-break:break-word;color:#1e293b;vertical-align:top}
  tr:nth-child(even) td{background:#f8fafc}
  .footer{margin-top:30px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px;display:flex;justify-content:space-between}
</style>
</head>
<body>
<h1>KQL Query Results</h1>
<div class="meta">Generated: ${dateStr} &nbsp;·&nbsp; Rows: ${result.row_count} &nbsp;·&nbsp; Look-back: ${days} days</div>
${explanation ? `<div class="intent"><strong>Query intent</strong>${esc(explanation)}</div>` : ''}
<div class="query-box">${esc(query)}</div>
<table>
  <thead><tr>${result.columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead>
  <tbody>${rows}</tbody>
</table>
<div class="footer">
  <span>Sentinel Vigil &nbsp;·&nbsp; Microsoft Sentinel</span>
  <span>Powered by AI-generated KQL</span>
</div>
</body>
</html>`;
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `KQL_Results_${new Date().toISOString().slice(0, 10)}.html`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const exportCSV = () => {
        if (!result) return;
        const csv = [
            result.columns.join(','),
            ...result.rows.map(r =>
                result.columns.map(c => JSON.stringify(r[c] ?? '')).join(',')
            ),
        ].join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `KQL_Results_${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

            {/* ── Header ── */}
            <div className="page-header">
                <div className="page-title">
                    <FontAwesomeIcon icon={faBolt} style={{ marginRight: 10, color: 'var(--pwc-orange)', fontSize: '0.9em' }} />
                    KQL Explorer
                </div>
                <div className="page-subtitle">
                    Describe what you want to find — AI generates the KQL, you review and run it
                </div>
            </div>

            <div style={{ flex: 1, overflow: 'auto', padding: '20px 28px', display: 'flex', flexDirection: 'column', gap: 16 }}>

                {/* ── Prompt Section ── */}
                <div className="card">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                        <FontAwesomeIcon icon={faWandMagicSparkles} style={{ color: 'var(--pwc-orange)', fontSize: 13 }} />
                        <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-primary)' }}>
                            Describe Your Query
                        </span>
                    </div>

                    <textarea
                        className="input"
                        value={prompt}
                        onChange={e => setPrompt(e.target.value)}
                        placeholder="e.g. Show me all failed sign-ins from outside the UK in the last 7 days, grouped by user and IP address..."
                        rows={3}
                        style={{ width: '100%', resize: 'vertical', fontFamily: 'inherit', fontSize: 13, lineHeight: 1.6, marginBottom: 12, boxSizing: 'border-box' }}
                        onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); generateQuery(); } }}
                    />

                    {/* Example chips */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16, alignItems: 'center' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', flexShrink: 0 }}>
                            <FontAwesomeIcon icon={faLightbulb} style={{ fontSize: 9 }} />
                            Try:
                        </span>
                        {EXAMPLE_PROMPTS.map(p => (
                            <button
                                key={p}
                                className="btn btn-ghost btn-sm"
                                style={{ fontSize: 11, padding: '3px 10px', borderRadius: 20, border: '1px solid var(--border)', lineHeight: 1.4 }}
                                onClick={() => setPrompt(p)}
                            >
                                {p}
                            </button>
                        ))}
                    </div>

                    {/* Controls row */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                        <button
                            className="btn btn-primary"
                            disabled={generating || !prompt.trim()}
                            onClick={generateQuery}
                            style={{ minWidth: 168 }}
                        >
                            {generating
                                ? <><FontAwesomeIcon icon={faSpinner} spin style={{ marginRight: 8 }} />Generating…</>
                                : <><FontAwesomeIcon icon={faWandMagicSparkles} style={{ marginRight: 8 }} />Generate KQL Query</>
                            }
                        </button>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Look-back:</span>
                            <select
                                className="input"
                                value={days}
                                onChange={e => setDays(e.target.value)}
                                style={{ height: 34, fontSize: 12, width: 110 }}
                            >
                                <option value="1">1 day</option>
                                <option value="7">7 days</option>
                                <option value="14">14 days</option>
                                <option value="30">30 days</option>
                                <option value="90">90 days</option>
                            </select>
                        </div>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Ctrl+Enter to generate</span>
                    </div>

                    {genError && (
                        <div style={{
                            marginTop: 12, padding: '10px 14px', display: 'flex', alignItems: 'flex-start', gap: 10,
                            background: 'rgba(192,57,43,0.07)', border: '1px solid rgba(192,57,43,0.25)', borderRadius: 8,
                        }}>
                            <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: 'var(--critical)', flexShrink: 0, marginTop: 1 }} />
                            <div>
                                <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--critical)', marginBottom: 2 }}>Generation failed</div>
                                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{genError}</div>
                            </div>
                            <button
                                onClick={() => setGenError(null)}
                                style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', flexShrink: 0 }}
                            >
                                <FontAwesomeIcon icon={faXmark} />
                            </button>
                        </div>
                    )}
                </div>

                {/* ── Generated Query Editor ── */}
                {queryReady && (
                    <div className="card fade-in" ref={queryRef as unknown as React.RefObject<HTMLDivElement>}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-primary)' }}>
                                    Generated Query
                                </span>
                                <span style={{
                                    fontSize: 10, fontWeight: 600, color: 'var(--low)',
                                    background: 'rgba(39,174,96,0.1)', padding: '2px 8px', borderRadius: 10,
                                }}>
                                    Editable — review before running
                                </span>
                            </div>
                            <button className="btn btn-ghost btn-sm" onClick={copyQuery} style={{ fontSize: 11, minWidth: 80 }}>
                                <FontAwesomeIcon
                                    icon={copied ? faCheck : faCopy}
                                    style={{ marginRight: 6, color: copied ? 'var(--low)' : undefined }}
                                />
                                {copied ? 'Copied!' : 'Copy'}
                            </button>
                        </div>

                        {explanation && (
                            <div style={{
                                marginBottom: 10, padding: '9px 13px', display: 'flex', alignItems: 'flex-start', gap: 9,
                                background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 7,
                            }}>
                                <FontAwesomeIcon icon={faCircleInfo} style={{ color: 'var(--info)', fontSize: 12, flexShrink: 0, marginTop: 2 }} />
                                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                    <span style={{ fontWeight: 700, color: 'var(--info)' }}>What this does: </span>
                                    {explanation}
                                </div>
                            </div>
                        )}

                        <textarea
                            ref={queryRef}
                            className="input"
                            value={query}
                            onChange={e => setQuery(e.target.value)}
                            rows={12}
                            style={{
                                width: '100%', resize: 'vertical', boxSizing: 'border-box',
                                fontFamily: '"JetBrains Mono", Consolas, "Courier New", monospace',
                                fontSize: 12, lineHeight: 1.7, marginBottom: 12,
                                background: 'var(--bg-deep, var(--bg-surface))',
                                color: 'var(--code-color, var(--text-primary))',
                            }}
                            onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runQuery(); } }}
                        />

                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                            <button
                                className="btn btn-primary"
                                disabled={running || !query.trim()}
                                onClick={runQuery}
                                style={{ minWidth: 140 }}
                            >
                                {running
                                    ? <><FontAwesomeIcon icon={faSpinner} spin style={{ marginRight: 8 }} />Running…</>
                                    : <><FontAwesomeIcon icon={faPlay} style={{ marginRight: 8 }} />Run Query</>
                                }
                            </button>
                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Ctrl+Enter to run</span>
                        </div>

                        {runError && (
                            <div style={{
                                marginTop: 12, padding: '10px 14px',
                                background: 'rgba(192,57,43,0.07)', border: '1px solid rgba(192,57,43,0.25)',
                                borderRadius: 8, fontSize: 12, color: 'var(--critical)',
                                fontFamily: '"JetBrains Mono", Consolas, monospace', lineHeight: 1.6,
                            }}>
                                <FontAwesomeIcon icon={faTriangleExclamation} style={{ marginRight: 8 }} />
                                {runError}
                            </div>
                        )}
                    </div>
                )}

                {/* ── Results ── */}
                {result && (
                    <div className="card fade-in">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-primary)' }}>
                                    Results
                                </span>
                                <span style={{ fontSize: 13, fontWeight: 700, color: result.row_count > 0 ? 'var(--info)' : 'var(--text-muted)' }}>
                                    {result.row_count.toLocaleString()} row{result.row_count !== 1 ? 's' : ''}
                                </span>
                                {elapsed !== null && (
                                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{elapsed}ms</span>
                                )}
                            </div>
                            {result.row_count > 0 && (
                                <div style={{ display: 'flex', gap: 8 }}>
                                    <button className="btn btn-ghost btn-sm" onClick={exportHTML} style={{ fontSize: 11 }}>
                                        <FontAwesomeIcon icon={faFileCode} style={{ marginRight: 6 }} />
                                        Export HTML
                                    </button>
                                    <button className="btn btn-ghost btn-sm" onClick={exportCSV} style={{ fontSize: 11 }}>
                                        <FontAwesomeIcon icon={faTable} style={{ marginRight: 6 }} />
                                        Export CSV
                                    </button>
                                </div>
                            )}
                        </div>

                        {result.row_count === 0 ? (
                            <div className="empty-state" style={{ padding: 32 }}>
                                <div className="empty-state-icon">
                                    <FontAwesomeIcon icon={faTable} style={{ opacity: 0.25 }} />
                                </div>
                                <div className="empty-state-text">Query returned no results</div>
                                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
                                    Try a wider look-back period or refine the query above
                                </div>
                            </div>
                        ) : (
                            <div className="data-table-wrap">
                                <table className="data-table">
                                    <thead>
                                        <tr>
                                            {result.columns.map(c => <th key={c}>{c}</th>)}
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {result.rows.map((row, i) => (
                                            <tr key={i}>
                                                {result.columns.map(c => (
                                                    <td
                                                        key={c}
                                                        title={String(row[c] ?? '')}
                                                        style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                                                    >
                                                        {String(row[c] ?? '')}
                                                    </td>
                                                ))}
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                )}

            </div>
        </div>
    );
}
