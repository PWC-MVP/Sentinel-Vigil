import { useState, useEffect } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { ReportLogPanel, type LogStep } from '../components/ReportLogPanel';
import {
    faCrosshairs, faPlay, faSearch, faCode, faXmark,
    faTriangleExclamation, faCircleCheck, faSpinner,
    faFileLines, faBrain
} from '@fortawesome/free-solid-svg-icons';

interface HuntQuery {
    id: string;
    title: string;
    category: string;
    mitre_technique: string;
    mitre_tactic: string;
    severity: string;
    description: string;
    query: string;
}
interface HuntResult {
    hunt_id: string;
    title: string;
    columns: string[];
    rows: Record<string, unknown>[];
    row_count: number;
    status: 'completed' | 'error' | 'running';
    error?: string;
}
interface HuntAnalysis {
    indication: string;
    remediation: string[];
    recommendations: string[];
}

function getTacticBadgeClass(tactic: string): string {
    const t = (tactic || '').toLowerCase();
    if (t.includes('identity') || t.includes('initial'))         return 'tactic-badge-identity';
    if (t.includes('execution'))                                  return 'tactic-badge-execution';
    if (t.includes('persist'))                                    return 'tactic-badge-persistence';
    if (t.includes('privilege') || t.includes('escalation'))     return 'tactic-badge-priv-esc';
    if (t.includes('defense') || t.includes('evasion'))          return 'tactic-badge-defense-evasion';
    if (t.includes('credential'))                                 return 'tactic-badge-credential';
    if (t.includes('collection'))                                 return 'tactic-badge-collection';
    if (t.includes('exfil'))                                      return 'tactic-badge-exfiltration';
    if (t.includes('lateral'))                                    return 'tactic-badge-lateral';
    return 'tactic-badge-default';
}

function sevBadge(s: string) {
    if (s === 'Critical' || s === 'High') return 'badge-critical';
    if (s === 'Medium') return 'badge-high';
    return 'badge-low';
}

const CAT_COLORS: Record<string, string> = {
    Identity: '#3498DB',
    Execution: '#E67E22',
    Persistence: '#8E44AD',
    'Privilege Escalation': '#E74C3C',
    'Defense Evasion': '#C0392B',
    'Credential Access': '#D35400',
    Collection: '#16A085',
    Exfiltration: '#2980B9',
    'Lateral Movement': '#F39C12',
    'Anonymous Infrastructure': '#7F8C8D',
};

export default function ThreatHunting() {
    const [categories, setCategories] = useState<string[]>([]);
    const [queries, setQueries] = useState<HuntQuery[]>([]);
    const [selectedCat, setSelectedCat] = useState('All');
    const [search, setSearch] = useState('');
    const [selectedHunt, setSelectedHunt] = useState<HuntQuery | null>(null);
    const [runningId, setRunningId] = useState<string | null>(null);
    const [results, setResults] = useState<Record<string, HuntResult>>({});
    const [days, setDays] = useState(7);
    const [customQuery, setCustomQuery] = useState('');
    const [customRunning, setCustomRunning] = useState(false);
    const [customResult, setCustomResult] = useState<HuntResult | null>(null);
    const [tab, setTab] = useState<'library' | 'custom'>('library');
    const [loading, setLoading] = useState(true);
    const [reportLoading, setReportLoading]   = useState(false);
    const [reportSuccess, setReportSuccess]   = useState<boolean | null>(null);
    const [reportError, setReportError]       = useState<string | null>(null);
    const [reportModel, setReportModel]       = useState('claude-sonnet-4-6');
    const [huntAnalyses, setHuntAnalyses]     = useState<Record<string, HuntAnalysis>>({});
    const [analyzingId, setAnalyzingId]       = useState<string | null>(null);

    const generateReport = async () => {
        setReportLoading(true);
        setReportError(null);
        setReportSuccess(null);
        try {
            const res = await axios.post(`/api/hunting/report?days=${days}&model=${reportModel}`, {}, { responseType: 'blob', timeout: 0 });
            const url = URL.createObjectURL(new Blob([res.data], { type: 'text/html' }));
            const a = document.createElement('a');
            a.href = url;
            a.download = `Hunting_Report_${new Date().toISOString().slice(0, 10)}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            setReportSuccess(true);
        } catch {
            setReportError('Report generation failed. Please try again.');
            setReportSuccess(false);
        } finally {
            setReportLoading(false);
        }
    };

    const HUNTING_LOG_STEPS: LogStep[] = [
        { level: 'info', msg: 'Connecting to Sentinel workspace…',          delay: 400 },
        { level: 'info', msg: 'Loading threat hunting library…',            delay: 2000 },
        { level: 'info', msg: `Executing ${queries.length} hunt queries in batch…`, delay: 4000 },
        { level: 'info', msg: 'Correlating MITRE ATT&CK coverage…',        delay: 9000 },
        { level: 'info', msg: 'Aggregating and scoring hunt results…',      delay: 14000 },
        { level: 'ai',   msg: 'Running LLM analysis with Claude…',          delay: 18000 },
        { level: 'ai',   msg: 'Generating hunt report document…',           delay: 23000 },
    ];

    useEffect(() => {
        Promise.all([
            axios.get('/api/hunting/categories'),
            axios.get('/api/hunting/library'),
        ]).then(([cats, lib]) => {
            setCategories(cats.data.categories || []);
            setQueries(lib.data.queries || []);
        }).finally(() => setLoading(false));
    }, []);

    const filtered = queries.filter(q =>
        (selectedCat === 'All' || q.category === selectedCat) &&
        (q.title.toLowerCase().includes(search.toLowerCase()) ||
         q.description.toLowerCase().includes(search.toLowerCase()) ||
         q.mitre_technique.toLowerCase().includes(search.toLowerCase()))
    );

    const runHunt = async (hunt: HuntQuery) => {
        setRunningId(hunt.id);
        setSelectedHunt(hunt);
        try {
            const res = await axios.post(`/api/hunting/run/${hunt.id}?days=${days}`);
            setResults(prev => ({ ...prev, [hunt.id]: res.data }));
        } catch (e: any) {
            setResults(prev => ({ ...prev, [hunt.id]: { hunt_id: hunt.id, title: hunt.title, columns: [], rows: [], row_count: 0, status: 'error', error: e.message } }));
        } finally {
            setRunningId(null);
        }
    };

    const analyzeHunt = async (hunt: HuntQuery, result: HuntResult) => {
        setAnalyzingId(hunt.id);
        try {
            const res = await axios.post('/api/hunting/analyze', {
                hunt_id: hunt.id,
                rows: result.rows.slice(0, 20),
                row_count: result.row_count,
                days,
            });
            setHuntAnalyses(prev => ({ ...prev, [hunt.id]: res.data }));
        } catch {
            // silently ignore — user can retry
        } finally {
            setAnalyzingId(null);
        }
    };

    const runCustom = async () => {
        if (!customQuery.trim()) return;
        setCustomRunning(true);
        setCustomResult(null);
        try {
            const res = await axios.post(`/api/hunting/run-custom?days=${days}`, { query: customQuery });
            setCustomResult(res.data);
        } catch (e: any) {
            setCustomResult({ hunt_id: 'custom', title: 'Custom Query', columns: [], rows: [], row_count: 0, status: 'error', error: e.message });
        } finally {
            setCustomRunning(false);
        }
    };

    if (loading) return (
        <div style={{ padding: 40, textAlign: 'center' }}>
            <div className="spinner spinner-lg" style={{ margin: '0 auto 12px' }} />
            <div className="text-muted">Loading threat hunting library…</div>
        </div>
    );

    const currentResult = selectedHunt ? results[selectedHunt.id] : null;

    return (
        <div>
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faCrosshairs} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Threat Hunting
                        </div>
                        <div className="page-subtitle">{queries.length} curated KQL hunting queries across {categories.length - 1} threat categories</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-card)', padding: '4px 12px', borderRadius: 8, border: '1px solid var(--border-color)' }}>
                            <span style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Look-back</span>
                            <select value={days} onChange={e => setDays(Number(e.target.value))}
                                style={{ background: 'none', border: 'none', color: 'var(--pwc-orange)', fontSize: 13, fontWeight: 700, cursor: 'pointer', outline: 'none', padding: '4px 0' }}>
                                <option value={0.5}>12 Hours</option>
                                <option value={1}>24 Hours</option>
                                <option value={2}>48 Hours</option>
                                <option value={3}>3 Days</option>
                                <option value={7}>7 Days</option>
                                <option value={14}>14 Days</option>
                                <option value={30}>30 Days</option>
                                <option value={60}>60 Days</option>
                                <option value={90}>90 Days</option>
                            </select>
                        </div>
                        <select
                            value={reportModel}
                            onChange={e => setReportModel(e.target.value)}
                            disabled={reportLoading}
                            className="form-select"
                            style={{ fontSize: 12, padding: '4px 8px', height: 34 }}
                        >
                            <option value="claude-sonnet-4-6">Sonnet 4.6</option>
                            <option value="claude-haiku-4-5">Haiku 4.5</option>
                        </select>
                        <button
                            className="btn btn-primary"
                            onClick={generateReport}
                            disabled={reportLoading}
                            title={`Run all ${queries.length} hunts and export a detailed HTML report`}
                            style={{ display: 'flex', alignItems: 'center', gap: 8 }}
                        >
                            {reportLoading
                                ? <><FontAwesomeIcon icon={faSpinner} spin />Running {queries.length} hunts…</>
                                : <><FontAwesomeIcon icon={faFileLines} />Generate Hunt Report</>}
                        </button>
                    </div>
                </div>

                {/* Tabs */}
                <div className="tabs" style={{ marginTop: 12, marginBottom: 0 }}>
                    <button className={`tab ${tab === 'library' ? 'active' : ''}`} onClick={() => setTab('library')}>
                        <FontAwesomeIcon icon={faCrosshairs} style={{ marginRight: 8 }} />Hunt Library ({queries.length})
                    </button>
                    <button className={`tab ${tab === 'custom' ? 'active' : ''}`} onClick={() => setTab('custom')}>
                        <FontAwesomeIcon icon={faCode} style={{ marginRight: 8 }} />Custom Query
                    </button>
                </div>
            </div>

            {(reportLoading || reportSuccess !== null) && (
                <div style={{ padding: '0 20px 4px' }}>
                    <ReportLogPanel
                        steps={HUNTING_LOG_STEPS}
                        loading={reportLoading}
                        success={reportSuccess}
                        error={reportError}
                        successMsg="Hunt report downloaded successfully"
                    />
                </div>
            )}

            <div className="page-content">
                {tab === 'library' && (
                    <div style={{ display: 'grid', gridTemplateColumns: selectedHunt ? '360px 1fr' : '1fr', gap: 20 }}>
                        {/* Left: Query List */}
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                            {/* Search + Filter */}
                            <div style={{ display: 'flex', gap: 8, flexDirection: 'column' }}>
                                <div style={{ position: 'relative' }}>
                                    <FontAwesomeIcon icon={faSearch} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 12 }} />
                                    <input
                                        value={search}
                                        onChange={e => setSearch(e.target.value)}
                                        placeholder="Search hunts, techniques, descriptions…"
                                        className="form-input"
                                        style={{ width: '100%', paddingLeft: 30, boxSizing: 'border-box' }}
                                    />
                                </div>
                                {categories && categories.length > 0 && (
                                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                        {categories.map(c => (
                                            <button
                                                key={c}
                                                className={`chip ${selectedCat === c ? 'active' : ''}`}
                                                onClick={() => setSelectedCat(c)}
                                            >
                                                {c}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>

                            {/* Query Cards */}
                            {filtered.length === 0 && (
                                <div className="empty-state"><div className="empty-state-text">No hunts match the filter</div></div>
                            )}
                            <div style={{ display: 'grid', gridTemplateColumns: selectedHunt ? '1fr' : 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16 }}>
                                {filtered.map(q => {
                                    const hasResult = !!results[q.id];
                                    const res = results[q.id];
                                    const isActive = selectedHunt?.id === q.id;
                                    const isRunning = runningId === q.id;
                                    return (
                                        <div key={q.id}
                                            className="card-elevated"
                                            onClick={() => setSelectedHunt(isActive ? null : q)}
                                            style={{
                                                padding: 18, cursor: 'pointer',
                                                outline: isActive ? '2px solid var(--brand)' : 'none',
                                            }}
                                        >
                                            {/* Header: severity badge + category */}
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                                                <span className={`badge ${sevBadge(q.severity)}`}>
                                                    {q.severity}
                                                </span>
                                                <span className="chip" style={{ fontSize: 10, padding: '2px 8px', cursor: 'default',
                                                    color: CAT_COLORS[q.category] || '#7F8C8D',
                                                    borderColor: `${CAT_COLORS[q.category] || '#7F8C8D'}40`,
                                                    background: `${CAT_COLORS[q.category] || '#7F8C8D'}12`,
                                                }}>
                                                    {q.category}
                                                </span>
                                            </div>
                                            {/* Title */}
                                            <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-primary)', marginBottom: 6, lineHeight: 1.4 }}>
                                                {q.title}
                                            </div>
                                            {/* MITRE tactic */}
                                            {q.mitre_tactic && (
                                                <div style={{ marginBottom: 8 }}>
                                                    <span className={`tactic-badge ${getTacticBadgeClass(q.mitre_tactic)}`}>
                                                        {q.mitre_tactic}
                                                    </span>
                                                </div>
                                            )}
                                            {/* Description */}
                                            <div style={{
                                                fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: 12,
                                                display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden',
                                            }}>
                                                {q.description}
                                            </div>
                                            {/* Footer */}
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'auto' }}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                    <code className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                                                        {q.mitre_technique}
                                                    </code>
                                                    {hasResult && (
                                                        <span className={`badge ${res.status === 'error' ? 'badge-critical' : res.row_count > 0 ? 'badge-high' : 'badge-low'}`} style={{ fontSize: 10 }}>
                                                            {res.status === 'error' ? '⚠ Error' : `${res.row_count} hits`}
                                                        </span>
                                                    )}
                                                </div>
                                                <button
                                                    className="btn btn-primary btn-sm"
                                                    onClick={e => { e.stopPropagation(); runHunt(q); }}
                                                    disabled={isRunning}
                                                >
                                                    {isRunning
                                                        ? <><FontAwesomeIcon icon={faSpinner} spin style={{ marginRight: 4 }} />Running…</>
                                                        : <><FontAwesomeIcon icon={faPlay} style={{ marginRight: 4 }} />Run Hunt</>}
                                                </button>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>

                        {/* Right: Detail Panel */}
                        {selectedHunt && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                                <div className="card">
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                                        <div>
                                            <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 6 }}>{selectedHunt.title}</div>
                                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                                <span style={{ fontSize: 10, fontWeight: 800, color: CAT_COLORS[selectedHunt.category] || '#7F8C8D', background: `${CAT_COLORS[selectedHunt.category] || '#7F8C8D'}18`, padding: '3px 10px', borderRadius: 12 }}>
                                                    {selectedHunt.category}
                                                </span>
                                                <span className={`badge ${sevBadge(selectedHunt.severity)}`}>{selectedHunt.severity}</span>
                                                <code className="mono" style={{ fontSize: 10, color: 'var(--brand)', background: 'var(--pwc-orange-light)', padding: '3px 8px', borderRadius: 6, fontWeight: 700 }}>{selectedHunt.mitre_technique}</code>
                                                <span className={`tactic-badge ${getTacticBadgeClass(selectedHunt.mitre_tactic)}`}>{selectedHunt.mitre_tactic}</span>
                                            </div>
                                        </div>
                                        <div style={{ display: 'flex', gap: 8 }}>
                                            <button className="btn btn-primary" onClick={() => runHunt(selectedHunt)} disabled={runningId === selectedHunt.id}>
                                                {runningId === selectedHunt.id
                                                    ? <><FontAwesomeIcon icon={faSpinner} spin style={{ marginRight: 8 }} />Running…</>
                                                    : <><FontAwesomeIcon icon={faPlay} style={{ marginRight: 8 }} />Run Hunt ({days}d)</>}
                                            </button>
                                            <button className="btn btn-ghost" onClick={() => setSelectedHunt(null)}>
                                                <FontAwesomeIcon icon={faXmark} />
                                            </button>
                                        </div>
                                    </div>
                                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: 14 }}>{selectedHunt.description}</div>
                                    <div style={{ background: 'var(--bg-base)', border: '1px solid var(--border-color)', borderRadius: 6, padding: '12px 14px' }}>
                                        <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8, letterSpacing: '0.06em' }}>KQL Query</div>
                                        <pre className="mono" style={{ margin: 0, fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text-primary)', lineHeight: 1.6 }}>{selectedHunt.query}</pre>
                                    </div>
                                </div>

                                {/* Results */}
                                {currentResult && (
                                    <div className="card" style={{ padding: 0 }}>
                                        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 10, alignItems: 'center' }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                <FontAwesomeIcon icon={currentResult.status === 'error' ? faTriangleExclamation : faCircleCheck}
                                                    style={{ color: currentResult.status === 'error' ? 'var(--critical)' : currentResult.row_count > 0 ? 'var(--high)' : 'var(--low)' }} />
                                                <span style={{ fontWeight: 700, fontSize: 13 }}>Results</span>
                                            </div>
                                            <span className={`badge ${currentResult.status === 'error' ? 'badge-critical' : currentResult.row_count > 0 ? 'badge-high' : 'badge-low'}`}>
                                                {currentResult.status === 'error' ? 'Error' : `${currentResult.row_count} rows`}
                                            </span>
                                            {currentResult.row_count > 0 && (
                                                <span style={{ fontSize: 11, color: 'var(--high)', fontWeight: 600, marginLeft: 4 }}>
                                                    ⚠ Investigate these findings
                                                </span>
                                            )}
                                            {currentResult.row_count === 0 && currentResult.status === 'completed' && (
                                                <span style={{ fontSize: 11, color: 'var(--low)', marginLeft: 4 }}>No matches — environment appears clean</span>
                                            )}
                                            {currentResult.row_count > 0 && currentResult.status === 'completed' && selectedHunt && !huntAnalyses[selectedHunt.id] && (
                                                <button
                                                    className="btn btn-sm btn-ghost"
                                                    style={{ marginLeft: 'auto', fontSize: 11, display: 'flex', alignItems: 'center', gap: 6, borderColor: '#3b82f640', color: '#93c5fd' }}
                                                    onClick={() => analyzeHunt(selectedHunt, currentResult)}
                                                    disabled={analyzingId === selectedHunt.id}
                                                >
                                                    {analyzingId === selectedHunt.id
                                                        ? <><FontAwesomeIcon icon={faSpinner} spin />Analysing…</>
                                                        : <><FontAwesomeIcon icon={faBrain} />Analyse with AI</>}
                                                </button>
                                            )}
                                        </div>
                                        {currentResult.status === 'error' ? (
                                            <div style={{ padding: 20, color: 'var(--critical)', fontSize: 12 }}>
                                                <FontAwesomeIcon icon={faTriangleExclamation} style={{ marginRight: 8 }} />
                                                {currentResult.error}
                                            </div>
                                        ) : currentResult.rows.length > 0 ? (
                                            <div className="data-table-wrap" style={{ maxHeight: 400 }}>
                                                <table className="data-table">
                                                    <thead>
                                                        <tr>{currentResult.columns.map(c => <th key={c}>{c}</th>)}</tr>
                                                    </thead>
                                                    <tbody>
                                                        {currentResult.rows.slice(0, 50).map((row, i) => (
                                                            <tr key={i}>
                                                                {currentResult.columns.map(c => (
                                                                    <td key={c} style={{ fontSize: 11 }}>
                                                                        {String(row[c] ?? '—').slice(0, 120)}
                                                                    </td>
                                                                ))}
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            </div>
                                        ) : null}

                                        {/* AI Analysis Panel */}
                                        {selectedHunt && huntAnalyses[selectedHunt.id] && (() => {
                                            const ai = huntAnalyses[selectedHunt.id];
                                            return (
                                                <div className="card-elevated" style={{ margin: '0 16px 16px', padding: '16px 20px' }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                                                        <FontAwesomeIcon icon={faBrain} style={{ color: 'var(--info)', fontSize: 13 }} />
                                                        <span className="badge badge-info" style={{ fontSize: 10, padding: '2px 10px' }}>AI Analysis</span>
                                                        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Powered by Claude</span>
                                                        <button
                                                            className="btn btn-sm btn-ghost"
                                                            style={{ marginLeft: 'auto', fontSize: 10, padding: '2px 8px' }}
                                                            onClick={() => analyzeHunt(selectedHunt, currentResult!)}
                                                            disabled={analyzingId === selectedHunt.id}
                                                            title="Re-run AI analysis"
                                                        >
                                                            {analyzingId === selectedHunt.id ? <FontAwesomeIcon icon={faSpinner} spin /> : '↻ Re-analyse'}
                                                        </button>
                                                    </div>

                                                    {/* Indication */}
                                                    {ai.indication && (
                                                        <div style={{
                                                            padding: '10px 14px',
                                                            borderRadius: 'var(--radius-md)',
                                                            marginBottom: 14,
                                                            background: ai.indication?.toLowerCase().includes('critical') ? 'rgba(192,57,43,0.08)'
                                                                      : ai.indication?.toLowerCase().includes('high')     ? 'rgba(230,126,34,0.08)'
                                                                      : 'rgba(39,174,96,0.08)',
                                                            border: `1px solid ${ai.indication?.toLowerCase().includes('critical') ? 'rgba(192,57,43,0.2)'
                                                                                : ai.indication?.toLowerCase().includes('high')    ? 'rgba(230,126,34,0.2)'
                                                                                : 'rgba(39,174,96,0.2)'}`,
                                                        }}>
                                                            <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 4 }}>Threat Indication</div>
                                                            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{ai.indication}</div>
                                                        </div>
                                                    )}

                                                    {/* Remediation */}
                                                    {ai.remediation && ai.remediation.length > 0 && (
                                                        <div style={{ marginBottom: 14 }}>
                                                            <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 8, color: 'var(--critical)' }}>
                                                                Remediation Steps
                                                            </div>
                                                            <ol style={{ paddingLeft: 16, margin: 0 }}>
                                                                {ai.remediation.map((r, i) => (
                                                                    <li key={i} style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4, lineHeight: 1.5 }}>
                                                                        {r}
                                                                    </li>
                                                                ))}
                                                            </ol>
                                                        </div>
                                                    )}

                                                    {/* Recommendations */}
                                                    {ai.recommendations && ai.recommendations.length > 0 && (
                                                        <div>
                                                            <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 8, color: 'var(--info)' }}>
                                                                Recommendations
                                                            </div>
                                                            <ul style={{ paddingLeft: 16, margin: 0 }}>
                                                                {ai.recommendations.map((r, i) => (
                                                                    <li key={i} style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4, lineHeight: 1.5 }}>
                                                                        {r}
                                                                    </li>
                                                                ))}
                                                            </ul>
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })()}
                                    </div>
                                )}
                            </div>
                        )}

                        {!selectedHunt && (
                            <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
                                <div className="empty-state">
                                    <div className="empty-state-icon"><FontAwesomeIcon icon={faCrosshairs} style={{ opacity: 0.2, fontSize: 40 }} /></div>
                                    <div className="empty-state-text">Select a hunt from the left to view its details and run it</div>
                                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
                                        Or click <strong>Run</strong> directly to execute and jump to results
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* Custom Query */}
                {tab === 'custom' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                        <div className="card">
                            <div className="card-title">
                                <FontAwesomeIcon icon={faCode} className="card-title-icon" />
                                Custom Hunting Query
                            </div>
                            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
                                Write any KQL query and run it against the workspace. Results are displayed below.
                            </div>
                            <textarea
                                value={customQuery}
                                onChange={e => setCustomQuery(e.target.value)}
                                placeholder={`// Enter your KQL hunting query here\nSigninLogs\n| where TimeGenerated > ago(7d)\n| where ResultType != 0\n| summarize FailureCount = count() by UserPrincipalName\n| sort by FailureCount desc`}
                                rows={10}
                                className="form-textarea mono"
                                style={{ width: '100%', fontSize: 12, lineHeight: 1.6, boxSizing: 'border-box', resize: 'vertical' }}
                                onKeyDown={e => { if (e.ctrlKey && e.key === 'Enter') runCustom(); }}
                            />
                            <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center' }}>
                                <button className="btn btn-primary" onClick={runCustom} disabled={customRunning || !customQuery.trim()}>
                                    {customRunning
                                        ? <><FontAwesomeIcon icon={faSpinner} spin style={{ marginRight: 8 }} />Running…</>
                                        : <><FontAwesomeIcon icon={faPlay} style={{ marginRight: 8 }} />Run Query</>}
                                </button>
                                <button className="btn btn-ghost" onClick={() => { setCustomQuery(''); setCustomResult(null); }}>
                                    <FontAwesomeIcon icon={faXmark} style={{ marginRight: 6 }} />Clear
                                </button>
                                <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 8 }}>Ctrl + Enter to run · Look-back: {days}d</span>
                            </div>
                        </div>

                        {customResult && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 10, alignItems: 'center' }}>
                                    <FontAwesomeIcon icon={customResult.status === 'error' ? faTriangleExclamation : faCircleCheck}
                                        style={{ color: customResult.status === 'error' ? 'var(--critical)' : 'var(--low)' }} />
                                    <span style={{ fontWeight: 700 }}>Query Results</span>
                                    <span className={`badge ${customResult.status === 'error' ? 'badge-critical' : 'badge-low'}`}>
                                        {customResult.status === 'error' ? 'Error' : `${customResult.row_count} rows`}
                                    </span>
                                </div>
                                {customResult.status === 'error' ? (
                                    <div style={{ padding: 20, color: 'var(--critical)', fontSize: 12 }}>{customResult.error}</div>
                                ) : customResult.rows.length > 0 ? (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead><tr>{customResult.columns.map(c => <th key={c}>{c}</th>)}</tr></thead>
                                            <tbody>
                                                {customResult.rows.slice(0, 100).map((row, i) => (
                                                    <tr key={i}>
                                                        {customResult.columns.map(c => (
                                                            <td key={c} style={{ fontSize: 11 }}>{String(row[c] ?? '—').slice(0, 150)}</td>
                                                        ))}
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                ) : (
                                    <div className="empty-state" style={{ padding: 24 }}>
                                        <div className="empty-state-icon"><FontAwesomeIcon icon={faCircleCheck} style={{ color: 'var(--low)', opacity: 0.6 }} /></div>
                                        <div className="empty-state-text">Query returned no results</div>
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
