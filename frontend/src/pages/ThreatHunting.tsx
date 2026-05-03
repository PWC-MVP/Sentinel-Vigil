import { useState, useEffect } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faCrosshairs, faPlay, faSearch, faCode, faXmark,
    faTriangleExclamation, faCircleCheck, faSpinner,
    faFilter, faChevronRight, faFileLines
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
    const [reportLoading, setReportLoading] = useState(false);
    const [reportError, setReportError] = useState<string | null>(null);

    const generateReport = async () => {
        setReportLoading(true);
        setReportError(null);
        try {
            const res = await axios.post(`/api/hunting/report?days=${days}`, {}, { responseType: 'blob' });
            const url = URL.createObjectURL(new Blob([res.data], { type: 'text/html' }));
            const a = document.createElement('a');
            a.href = url;
            a.download = `Hunting_Report_${new Date().toISOString().slice(0, 10)}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch {
            setReportError('Report generation failed. Please try again.');
        } finally {
            setReportLoading(false);
        }
    };

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
                                <option value={1}>24 Hours</option>
                                <option value={7}>7 Days</option>
                                <option value={14}>14 Days</option>
                                <option value={30}>30 Days</option>
                            </select>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
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
                            {reportError && (
                                <span style={{ fontSize: 11, color: 'var(--critical)' }}>
                                    <FontAwesomeIcon icon={faTriangleExclamation} style={{ marginRight: 4 }} />{reportError}
                                </span>
                            )}
                        </div>
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

            <div className="page-content">
                {tab === 'library' && (
                    <div style={{ display: 'grid', gridTemplateColumns: selectedHunt ? '360px 1fr' : '1fr', gap: 20 }}>
                        {/* Left: Query List */}
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                            {/* Search + Filter */}
                            <div style={{ display: 'flex', gap: 8, flexDirection: 'column' }}>
                                <div style={{ position: 'relative' }}>
                                    <FontAwesomeIcon icon={faSearch} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 12 }} />
                                    <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search hunts, techniques, descriptions…"
                                        style={{ width: '100%', paddingLeft: 30, padding: '8px 10px 8px 30px', border: '1px solid var(--border-color)', borderRadius: 8, fontSize: 12, background: 'var(--bg-card)', color: 'var(--text-primary)', boxSizing: 'border-box' }} />
                                </div>
                                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                                    <FontAwesomeIcon icon={faFilter} style={{ color: 'var(--text-muted)', fontSize: 11 }} />
                                    {categories.map(c => (
                                        <button key={c} onClick={() => setSelectedCat(c)}
                                            className={`btn btn-sm ${selectedCat === c ? 'btn-primary' : 'btn-ghost'}`}
                                            style={{ borderRadius: 20, fontSize: 10, padding: '3px 10px' }}>
                                            {c}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Query Cards */}
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                {filtered.length === 0 && (
                                    <div className="empty-state"><div className="empty-state-text">No hunts match the filter</div></div>
                                )}
                                {filtered.map(q => {
                                    const hasResult = !!results[q.id];
                                    const res = results[q.id];
                                    const isActive = selectedHunt?.id === q.id;
                                    const isRunning = runningId === q.id;
                                    const catColor = CAT_COLORS[q.category] || '#7F8C8D';
                                    return (
                                        <div key={q.id}
                                            onClick={() => setSelectedHunt(q)}
                                            style={{
                                                background: isActive ? 'var(--bg-higher)' : 'var(--bg-card)',
                                                border: `1px solid ${isActive ? 'var(--brand)' : 'var(--border-color)'}`,
                                                borderRadius: 10, padding: '12px 14px', cursor: 'pointer',
                                                transition: 'all 0.15s', boxShadow: isActive ? '0 0 0 2px rgba(208,74,2,0.15)' : '0 1px 3px rgba(0,0,0,0.04)',
                                            }}
                                            onMouseEnter={e => { if (!isActive) e.currentTarget.style.borderColor = 'var(--brand)'; }}
                                            onMouseLeave={e => { if (!isActive) e.currentTarget.style.borderColor = 'var(--border-color)'; }}
                                        >
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                                                <div style={{ flex: 1, paddingRight: 8 }}>
                                                    <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>{q.title}</div>
                                                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                                                        <span style={{ fontSize: 9, fontWeight: 800, color: catColor, background: `${catColor}18`, padding: '2px 7px', borderRadius: 10 }}>{q.category}</span>
                                                        <span className={`badge ${sevBadge(q.severity)}`} style={{ fontSize: 9 }}>{q.severity}</span>
                                                        <code style={{ fontSize: 9, color: 'var(--text-muted)', background: 'var(--bg-base)', padding: '2px 5px', borderRadius: 4 }}>{q.mitre_technique}</code>
                                                    </div>
                                                </div>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                                                    {hasResult && (
                                                        <span style={{ fontSize: 10, fontWeight: 700, color: res.status === 'error' ? 'var(--critical)' : res.row_count > 0 ? 'var(--high)' : 'var(--low)' }}>
                                                            {res.status === 'error' ? '⚠ Error' : `${res.row_count} hits`}
                                                        </span>
                                                    )}
                                                    <button
                                                        className="btn btn-sm btn-primary"
                                                        style={{ padding: '4px 10px', fontSize: 10, borderRadius: 6 }}
                                                        onClick={e => { e.stopPropagation(); runHunt(q); }}
                                                        disabled={isRunning}
                                                    >
                                                        {isRunning
                                                            ? <FontAwesomeIcon icon={faSpinner} spin />
                                                            : <FontAwesomeIcon icon={faPlay} />}
                                                        {' '}{isRunning ? 'Running' : 'Run'}
                                                    </button>
                                                    <FontAwesomeIcon icon={faChevronRight} style={{ fontSize: 10, color: 'var(--text-muted)', opacity: isActive ? 1 : 0.4 }} />
                                                </div>
                                            </div>
                                            <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>{q.description}</div>
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
                                                <code style={{ fontSize: 10, color: 'var(--brand)', background: 'var(--pwc-orange-light)', padding: '3px 8px', borderRadius: 6, fontWeight: 700 }}>{selectedHunt.mitre_technique}</code>
                                                <span style={{ fontSize: 11, color: 'var(--text-muted)', padding: '3px 0' }}>{selectedHunt.mitre_tactic}</span>
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
                                        <pre style={{ margin: 0, fontSize: 11, fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text-primary)', lineHeight: 1.6 }}>{selectedHunt.query}</pre>
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
                                style={{
                                    width: '100%', fontFamily: 'JetBrains Mono, monospace', fontSize: 12, lineHeight: 1.6,
                                    padding: '12px 14px', border: '1px solid var(--border-color)', borderRadius: 8,
                                    background: 'var(--bg-base)', color: 'var(--text-primary)', resize: 'vertical',
                                    boxSizing: 'border-box',
                                }}
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
                                    <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                                        <FontAwesomeIcon icon={faCircleCheck} style={{ color: 'var(--low)', marginRight: 8 }} />
                                        Query returned no results
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
