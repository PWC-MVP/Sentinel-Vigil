import { useState, useEffect, useRef, Fragment, useMemo } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faDatabase, faSpinner, faRefresh, faChevronRight, faChevronDown,
    faSearch, faArrowUp, faArrowDown, faXmark, faRobot,
    faCode, faPlay, faCheckCircle, faTriangleExclamation,
    faCircleInfo, faTable, faPlus, faFilter, faWrench, faClock, faPaperPlane,
    faFolderOpen,
} from '@fortawesome/free-solid-svg-icons';
import { http as axios } from '../api/client';

const TIME_OPTIONS = [
    { value: '1h', label: 'Last 1 hour' },
    { value: '4h', label: 'Last 4 hours' },
    { value: '12h', label: 'Last 12 hours' },
    { value: '24h', label: 'Last 24 hours' },
    { value: '7d', label: 'Last 7 days' },
    { value: '30d', label: 'Last 30 days' },
];

const TIME_TO_DAYS: Record<string, number> = {
    '1h': 1, '4h': 1, '12h': 1, '24h': 1, '7d': 7, '30d': 30,
};

interface TableInfo { DataType: string; SizeMB?: number; Columns?: number; Custom?: boolean; }
interface ChatMessage { role: 'user' | 'assistant'; content: string; }
interface LogResult { columns: string[]; rows: Record<string, unknown>[]; row_count: number; }
interface ColFilter { column: string; value: string; }
interface ParserStep { label: string; status: 'running' | 'done' | 'error'; detail?: string; }
interface FnParam { type: string; name: string; defaultValue: string; }
interface FunctionInfo { id: string; alias: string; displayName: string; category: string; query: string; }

const KQL_TYPES = ['string', 'int', 'long', 'real', 'bool', 'datetime', 'timespan', 'dynamic'];

export default function KQLExplorer() {
    // ── tables ──────────────────────────────────────────────────
    const [tables, setTables] = useState<TableInfo[]>([]);
    const [tabLoading, setTabLoading] = useState(false);
    const [tabError, setTabError] = useState<string | null>(null);
    const [tableSearch, setTableSearch] = useState('');
    const [customOnly, setCustomOnly] = useState(false);
    const [hideEmpty, setHideEmpty] = useState(true);
    const [timeRange, setTimeRange] = useState('24h');

    // ── expanded table + logs ────────────────────────────────────
    const [expanded, setExpanded] = useState<string | null>(null);
    const [logs, setLogs] = useState<LogResult | null>(null);
    const [logsLoading, setLogsLoad] = useState(false);
    const [logsError, setLogsError] = useState<string | null>(null);

    // ── log filters ──────────────────────────────────────────────
    const [globSearch, setGlobSearch] = useState('');
    const [colFilters, setColFilters] = useState<ColFilter[]>([]);
    const [addingF, setAddingF] = useState(false);
    const [newCol, setNewCol] = useState('');
    const [newVal, setNewVal] = useState('');
    const [sortCol, setSortCol] = useState('TimeGenerated');
    const [sortDesc, setSortDesc] = useState(true);
    const [expRows, setExpRows] = useState<Set<number>>(new Set());

    // ── parser ───────────────────────────────────────────────────
    const [parserOpen, setParserOpen] = useState(false);
    const [parserKQL, setParserKQL] = useState('');
    const [parserAlias, setAlias] = useState('');
    const [parserNote, setNote] = useState('');
    const [creating, setCreating] = useState(false);
    const [parserErr, setParserErr] = useState<string | null>(null);
    const [parserSteps, setParserSteps] = useState<ParserStep[]>([]);
    const [runResult, setRunResult] = useState<LogResult | null>(null);
    const [parserValid, setParserValid] = useState(false); // true only after a successful run
    const [running, setRunning] = useState(false);
    const [implementing, setImpl] = useState(false);
    const [implSuccess, setImplSucc] = useState<string | null>(null);
    const [implError, setImplErr] = useState<string | null>(null);
    const [expRunRows, setExpRunRows] = useState<Set<number>>(new Set());

    // ── initial parser request ────────────────────────────────────
    const [parserRequest, setParserRequest] = useState('');

    // ── existing parser loaded into editor ────────────────────────
    const [loadedFromAlias, setLoadedFromAlias] = useState<string | null>(null);

    // ── chat ─────────────────────────────────────────────────────
    const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
    const [chatInput, setChatInput] = useState('');
    const [chatLoading, setChatLoad] = useState(false);
    const chatEndRef = useRef<HTMLDivElement>(null);

    // ── workspace functions panel ─────────────────────────────────
    const [wsFunctions, setWsFunctions] = useState<FunctionInfo[]>([]);
    const [fnLoading, setFnLoading] = useState(false);
    const [fnError, setFnError] = useState<string | null>(null);
    const [activeSection, setActiveSection] = useState<'tables' | 'functions'>('tables');
    const [expandedFn, setExpandedFn] = useState<string | null>(null);
    const [fnSearch, setFnSearch] = useState('');

    const toggleRunRow = (i: number) => setExpRunRows(prev => {
        const s = new Set(prev); s.has(i) ? s.delete(i) : s.add(i); return s;
    });

    // ── drawer resize ────────────────────────────────────────────
    const [drawerWidth, setDrawerWidth] = useState(560);
    const dragRef = useRef<{ startX: number; startW: number } | null>(null);

    const onDrawerDragStart = (e: React.MouseEvent) => {
        e.preventDefault();
        dragRef.current = { startX: e.clientX, startW: drawerWidth };
        const onMove = (ev: MouseEvent) => {
            if (!dragRef.current) return;
            const delta = dragRef.current.startX - ev.clientX;
            setDrawerWidth(Math.min(window.innerWidth - 60, Math.max(360, dragRef.current.startW + delta)));
        };
        const onUp = () => {
            dragRef.current = null;
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
        };
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    };

    // ── save-as-function modal ────────────────────────────────────
    const [saveModal, setSaveModal] = useState(false);
    const [saveName, setSaveName] = useState('');
    const [saveCategory, setSaveCategory] = useState('Parser');
    const [saveParams, setSaveParams] = useState<FnParam[]>([]);

    useEffect(() => { loadTables(); }, []);
    useEffect(() => {
        if (expanded) fetchLogs(expanded, globSearch, colFilters, sortCol, sortDesc);
    }, [timeRange]); // eslint-disable-line react-hooks/exhaustive-deps
    useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [chatMessages]);

    // ── API helpers ───────────────────────────────────────────────

    const loadTables = async () => {
        setTabLoading(true); setTabError(null);
        try {
            const r = await axios.get('/api/kql/tables', { timeout: 60000 });
            setTables(r.data.rows || []);
        } catch (e: unknown) {
            const err = e as { response?: { data?: { detail?: string } }; message?: string };
            setTabError(err?.response?.data?.detail ?? err?.message ?? 'Failed to load tables');
        } finally { setTabLoading(false); }
    };

    const loadFunctions = async () => {
        setFnLoading(true); setFnError(null);
        try {
            const r = await axios.get('/api/kql/list-functions', { timeout: 60000 });
            setWsFunctions(r.data.functions || []);
        } catch (e: unknown) {
            const err = e as { response?: { data?: { detail?: string } }; message?: string };
            setFnError(err?.response?.data?.detail ?? err?.message ?? 'Failed to load functions');
        } finally { setFnLoading(false); }
    };

    const fetchLogs = async (
        table: string, search: string, filters: ColFilter[], sort: string, desc: boolean,
    ) => {
        setLogsLoad(true); setLogsError(null);
        try {
            const cfMap: Record<string, string> = {};
            filters.forEach(f => { cfMap[f.column] = f.value; });
            const r = await axios.post('/api/kql/table-logs', {
                table, time_filter: timeRange, search,
                column_filters: cfMap, sort_column: sort, sort_desc: desc, limit: 200,
            }, { timeout: 60000 });
            setLogs(r.data);
        } catch (e: unknown) {
            const err = e as { response?: { data?: { detail?: string } }; message?: string };
            setLogsError(err?.response?.data?.detail ?? err?.message ?? 'Failed to load logs');
        } finally { setLogsLoad(false); }
    };

    const openTable = async (name: string) => {
        if (expanded === name) {
            setExpanded(null); setLogs(null); setParserOpen(false);
            setGlobSearch(''); setColFilters([]); setSortCol('TimeGenerated'); setSortDesc(true);
            setExpRows(new Set()); return;
        }
        setExpanded(name); setLogs(null);
        setParserOpen(true); setParserKQL(''); setAlias(''); setNote('');
        setParserSteps([]); setParserErr(null);
        setRunResult(null); setGlobSearch(''); setColFilters([]);
        setSortCol('TimeGenerated'); setSortDesc(true); setExpRows(new Set());
        setImplSucc(null); setImplErr(null);
        setChatMessages([]); setChatInput(''); setParserRequest('');
        setLoadedFromAlias(null);
        // Pre-load workspace functions so related-parsers panel is populated
        if (wsFunctions.length === 0 && !fnLoading) loadFunctions();
        await fetchLogs(name, '', [], 'TimeGenerated', true);
    };

    const loadExistingParser = (fn: FunctionInfo) => {
        setParserKQL(fn.query || '');
        setAlias(fn.alias || '');
        setNote(`Loaded from workspace function: ${fn.displayName || fn.alias}`);
        setParserValid(true);
        setLoadedFromAlias(fn.alias);
        setParserSteps([]);
        setRunResult(null);
        setParserErr(null);
        setChatMessages([]);
        setChatInput('');
        setImplSucc(null);
        setImplErr(null);
    };

    const handleSort = async (col: string) => {
        const desc = col === sortCol ? !sortDesc : true;
        setSortCol(col); setSortDesc(desc);
        if (expanded) fetchLogs(expanded, globSearch, colFilters, col, desc);
    };

    const applySearch = () => {
        if (expanded) fetchLogs(expanded, globSearch, colFilters, sortCol, sortDesc);
    };

    const addFilter = () => {
        if (!newCol || !newVal) return;
        const f = [...colFilters, { column: newCol, value: newVal }];
        setColFilters(f); setNewCol(''); setNewVal(''); setAddingF(false);
        if (expanded) fetchLogs(expanded, globSearch, f, sortCol, sortDesc);
    };

    const removeFilter = (i: number) => {
        const f = colFilters.filter((_, idx) => idx !== i);
        setColFilters(f);
        if (expanded) fetchLogs(expanded, globSearch, f, sortCol, sortDesc);
    };

    const toggleRow = (i: number) => {
        setExpRows(prev => {
            const s = new Set(prev);
            s.has(i) ? s.delete(i) : s.add(i);
            return s;
        });
    };

    const parserRun = async (requestOverride?: string) => {
        if (!logs || !expanded) return;
        setCreating(true); setParserErr(null); setParserValid(false);
        setParserSteps([]); setRunResult(null); setExpRunRows(new Set());
        setParserKQL(''); setAlias(''); setNote('');
        setImplSucc(null); setImplErr(null);
        setChatMessages([]); setChatInput('');
        setLoadedFromAlias(null);

        const upsertStep = (label: string, status: ParserStep['status'], detail?: string) =>
            setParserSteps(prev => {
                const idx = prev.findIndex(s => s.label === label);
                const step: ParserStep = { label, status, detail };
                if (idx >= 0) { const next = [...prev]; next[idx] = step; return next; }
                return [...prev, step];
            });

        try {
            const resp = await fetch('/api/kql/parser-run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    table: expanded,
                    sample_logs: logs.rows.slice(0, 10),
                    columns: logs.columns,
                    days: TIME_TO_DAYS[timeRange] || 1,
                    user_request: requestOverride ?? parserRequest,
                }),
            });

            if (!resp.ok || !resp.body) {
                setParserErr((await resp.text()) || 'Parser run failed');
                return;
            }

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buf = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += decoder.decode(value, { stream: true });
                const parts = buf.split('\n\n');
                buf = parts.pop() ?? '';
                for (const part of parts) {
                    const dataLine = part.split('\n').find(l => l.startsWith('data: '));
                    if (!dataLine) continue;
                    try {
                        const evt = JSON.parse(dataLine.slice(6));
                        if (evt.type === 'step') upsertStep(evt.label, evt.status, evt.detail);
                        if (evt.type === 'query') { setParserKQL(evt.query); setAlias(evt.alias); setNote(evt.explanation); }
                        if (evt.type === 'result') setRunResult(evt.data);
                        if (evt.type === 'done') {
                            if (evt.success) setParserValid(true);
                            else if (evt.error) setParserErr(evt.error);
                        }
                    } catch { /* ignore malformed SSE line */ }
                }
            }
        } catch (e: unknown) {
            const err = e as { message?: string };
            setParserErr(err?.message ?? 'Parser run failed');
        } finally { setCreating(false); }
    };

    const runParser = async () => {
        if (!parserKQL.trim()) return;
        setRunning(true); setParserErr(null); setRunResult(null); setParserValid(false);
        // Append run-with-fix steps after existing steps (don't clear generation steps)
        const upsertStep = (label: string, status: ParserStep['status'], detail?: string) =>
            setParserSteps(prev => {
                const idx = prev.findIndex(s => s.label === label);
                const step: ParserStep = { label, status, detail };
                if (idx >= 0) { const next = [...prev]; next[idx] = step; return next; }
                return [...prev, step];
            });

        try {
            const resp = await fetch('/api/kql/run-with-fix', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: parserKQL, days: TIME_TO_DAYS[timeRange] || 1 }),
            });
            if (!resp.ok || !resp.body) { setParserErr((await resp.text()) || 'Run failed'); return; }

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buf = '';
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += decoder.decode(value, { stream: true });
                const parts = buf.split('\n\n'); buf = parts.pop() ?? '';
                for (const part of parts) {
                    const dataLine = part.split('\n').find(l => l.startsWith('data: '));
                    if (!dataLine) continue;
                    try {
                        const evt = JSON.parse(dataLine.slice(6));
                        if (evt.type === 'step') upsertStep(evt.label, evt.status, evt.detail);
                        if (evt.type === 'query' && evt.query) setParserKQL(evt.query);
                        if (evt.type === 'result') setRunResult(evt.data);
                        if (evt.type === 'done') {
                            if (evt.success) setParserValid(true);
                            else if (evt.error) setParserErr(evt.error);
                        }
                    } catch { /* ignore */ }
                }
            }
        } catch (e: unknown) {
            const err = e as { message?: string };
            setParserErr(err?.message ?? 'Run failed');
        } finally { setRunning(false); }
    };

    const openSaveModal = () => {
        setSaveName(parserAlias);
        setSaveCategory('Parser');
        setSaveParams([]);
        setImplErr(null);
        setSaveModal(true);
    };

    const implementParser = async () => {
        if (!parserKQL || !expanded) return;
        setImpl(true); setImplErr(null);
        const name = saveName.trim() || parserAlias;
        const paramStr = saveParams
            .filter(p => p.name.trim())
            .map(p => `${p.name.trim()}:${p.type}${p.defaultValue.trim() ? `=${p.defaultValue.trim()}` : ''}`)
            .join(', ');
        try {
            const r = await axios.post('/api/kql/save-function', {
                function_name: name,
                display_name: name,   // same as alias so portal search finds it
                query: parserKQL,
                category: saveCategory.trim() || 'Parser',
                function_parameters: paramStr,
            }, { timeout: 30000 });
            const verified: boolean = r.data.verified !== false;
            const alias: string = r.data.alias || name;
            setImplSucc(alias);
            setSaveModal(false);
            if (!verified) {
                // alias didn't come back yet — show a note, not a hard error
                setImplErr(`Function sent to Azure. If it doesn't appear in the portal within 60 s, check server logs for [save-function] lines.`);
            }
        } catch (e: unknown) {
            const err = e as { response?: { data?: { detail?: string } }; message?: string };
            setImplErr(err?.response?.data?.detail ?? err?.message ?? 'Failed to implement');
        } finally { setImpl(false); }
    };

    const sendChat = async () => {
        if (!chatInput.trim() || !parserKQL || !expanded || chatLoading) return;
        const userMsg = chatInput.trim();
        setChatInput('');
        setChatMessages(prev => [...prev, { role: 'user', content: userMsg }]);
        setChatLoad(true);
        setParserErr(null);

        try {
            const resp = await fetch('/api/kql/parser-chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    table: expanded,
                    columns: (logs?.columns ?? []).slice(0, 30),
                    sample_logs: logs?.rows.slice(0, 5) ?? [],
                    current_query: parserKQL.slice(0, 6000),
                    message: userMsg,
                    days: TIME_TO_DAYS[timeRange] || 1,
                    related_parsers: relatedParsers.slice(0, 3).map(fn => ({
                        alias: fn.alias,
                        display_name: fn.displayName,
                        query: fn.query,
                    })),
                }),
            });

            if (!resp.ok || !resp.body) {
                const errText = await resp.text();
                setChatMessages(prev => [...prev, { role: 'assistant', content: errText || 'Request failed' }]);
                return;
            }

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buf = '';
            let assistantContent = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += decoder.decode(value, { stream: true });
                const parts = buf.split('\n\n');
                buf = parts.pop() ?? '';
                for (const part of parts) {
                    const dataLine = part.split('\n').find(l => l.startsWith('data: '));
                    if (!dataLine) continue;
                    try {
                        const evt = JSON.parse(dataLine.slice(6));
                        if (evt.type === 'query' && evt.query) {
                            setParserKQL(evt.query);
                            if (evt.explanation) assistantContent = evt.explanation;
                        }
                        if (evt.type === 'answer' && evt.text) {
                            assistantContent = evt.text + (assistantContent ? '\n\n' + assistantContent : '');
                        }
                        if (evt.type === 'result') {
                            setRunResult(evt.data);
                            setParserValid(true);
                            setExpRunRows(new Set());
                        }
                        if (evt.type === 'done' && !evt.success && evt.error) {
                            const raw: string = evt.error;
                            let friendly = raw;
                            if (/getaddrinfo|network error|connecterror|connection refused/i.test(raw))
                                friendly = 'Could not reach the AI service — check your network connection or Azure endpoint configuration.';
                            else if (/empty response|code fence/i.test(raw))
                                friendly = 'The AI returned an empty response. Please try again.';
                            else if (/rate.?limit|429/i.test(raw))
                                friendly = 'AI service rate limit reached. Please wait a moment and try again.';
                            else if (/LLM not configured/i.test(raw))
                                friendly = 'AI service is not configured. Add AZURE_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY to .env.';
                            assistantContent = assistantContent || friendly;
                        }
                    } catch { /* ignore malformed SSE */ }
                }
            }

            setChatMessages(prev => [...prev, {
                role: 'assistant',
                content: assistantContent || 'Parser updated — check the KQL editor above.',
            }]);
        } catch (e: unknown) {
            const err = e as { message?: string };
            setChatMessages(prev => [...prev, { role: 'assistant', content: err?.message ?? 'Request failed' }]);
        } finally {
            setChatLoad(false);
        }
    };

    const filtered = tables.filter(t => {
        if (customOnly && !t.Custom) return false;
        if (hideEmpty && (t.SizeMB == null || t.SizeMB === 0)) return false;
        if (tableSearch && !t.DataType?.toLowerCase().includes(tableSearch.toLowerCase())) return false;
        return true;
    });

    const filteredFns = wsFunctions.filter(fn => {
        if (!fnSearch) return true;
        const q = fnSearch.toLowerCase();
        return (fn.displayName?.toLowerCase().includes(q) || fn.alias?.toLowerCase().includes(q) || fn.category?.toLowerCase().includes(q));
    });

    // Workspace functions whose alias/query are related to the currently expanded table
    const relatedParsers = useMemo<FunctionInfo[]>(() => {
        if (!expanded || wsFunctions.length === 0) return [];
        const lower = expanded.toLowerCase();
        // strip common separators so "AuditLogs" matches "audit_logs_parser" etc.
        const stripped = lower.replace(/[_\-\s]/g, '');
        return wsFunctions.filter(fn => {
            const alias   = (fn.alias       || '').toLowerCase().replace(/[_\-\s]/g, '');
            const display = (fn.displayName || '').toLowerCase().replace(/[_\-\s]/g, '');
            const qStart  = (fn.query       || '').trimStart().toLowerCase();
            return alias.includes(stripped) || display.includes(stripped) || qStart.startsWith(lower);
        });
    }, [expanded, wsFunctions]);

    // ── render ────────────────────────────────────────────────────
    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

            {/* Header */}
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faDatabase} style={{ marginRight: 10, color: 'var(--pwc-orange)', fontSize: '0.9em' }} />
                            Log Parser
                        </div>
                        <div className="page-subtitle">
                            Browse workspace tables, explore logs, and build AI-powered KQL parsers
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                        <button
                            onClick={() => setActiveSection('tables')}
                            style={{
                                display: 'flex', alignItems: 'center', gap: 8,
                                height: 36, fontSize: 12.5, paddingInline: 14, flexShrink: 0,
                                borderRadius: 8,
                                border: `1px solid ${activeSection === 'tables' ? 'var(--pwc-orange)' : 'var(--border)'}`,
                                background: activeSection === 'tables' ? 'var(--pwc-orange-light)' : '#FFFFFF',
                                cursor: 'pointer',
                                color: activeSection === 'tables' ? 'var(--pwc-orange)' : 'var(--text-secondary)',
                                fontWeight: 500,
                                boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
                                transition: 'all 0.15s',
                            }}
                        >
                            <FontAwesomeIcon icon={faDatabase} style={{ fontSize: 11 }} />
                            Workspace Tables
                            {tables.length > 0 && (
                                <span className="badge badge-muted" style={{ fontSize: 10, marginLeft: 2 }}>{filtered.length}</span>
                            )}
                        </button>
                        <button
                            onClick={() => {
                                setActiveSection('functions');
                                if (wsFunctions.length === 0) loadFunctions();
                            }}
                            style={{
                                display: 'flex', alignItems: 'center', gap: 8,
                                height: 36, fontSize: 12.5, paddingInline: 14, flexShrink: 0,
                                borderRadius: 8,
                                border: `1px solid ${activeSection === 'functions' ? 'var(--pwc-orange)' : 'var(--border)'}`,
                                background: activeSection === 'functions' ? 'var(--pwc-orange-light)' : '#FFFFFF',
                                cursor: 'pointer',
                                color: activeSection === 'functions' ? 'var(--pwc-orange)' : 'var(--text-secondary)',
                                fontWeight: 500,
                                boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
                                transition: 'all 0.15s',
                            }}
                        >
                            <FontAwesomeIcon icon={faCode} style={{ fontSize: 11 }} />
                            Workspace Functions
                            {wsFunctions.length > 0 && (
                                <span className="badge badge-muted" style={{ fontSize: 10, marginLeft: 2 }}>{wsFunctions.length}</span>
                            )}
                        </button>
                    </div>
                </div>
            </div>

            <div style={{ flex: 1, overflow: 'auto', padding: '20px 28px', display: 'flex', flexDirection: 'column', gap: 16 }}>

                {/* Toolbar — tables only */}
                {activeSection === 'tables' && <div style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    background: 'linear-gradient(135deg, #FAFAF9 0%, #FFFFFF 100%)',
                    border: '1px solid var(--border)',
                    borderRadius: 12,
                    padding: '10px 14px',
                    boxShadow: '0 1px 4px rgba(0,0,0,0.05), inset 0 0 0 1px rgba(255,255,255,0.9)',
                }}>
                    {/* Search */}
                    <div style={{ position: 'relative', flex: 1, minWidth: 0 }}>
                        <FontAwesomeIcon icon={faSearch} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', fontSize: 11, color: 'var(--text-muted)', pointerEvents: 'none' }} />
                        <input
                            className="form-input"
                            placeholder="Search tables…"
                            value={tableSearch}
                            onChange={e => setTableSearch(e.target.value)}
                            style={{ paddingLeft: 34, height: 36, fontSize: 12.5, width: '100%', boxSizing: 'border-box', borderRadius: 8 }}
                        />
                    </div>

                    <div style={{ width: 1, height: 22, background: 'var(--border)', flexShrink: 0 }} />

                    {/* Time range */}
                    <div style={{ position: 'relative', flexShrink: 0 }}>
                        <FontAwesomeIcon icon={faClock} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', fontSize: 11, color: 'var(--pwc-orange)', pointerEvents: 'none', zIndex: 1 }} />
                        <select
                            className="form-select"
                            value={timeRange}
                            onChange={e => setTimeRange(e.target.value)}
                            style={{
                                height: 36, fontSize: 12, width: 155, paddingLeft: 28,
                                borderRadius: 8, fontWeight: 500,
                                border: '1px solid var(--pwc-orange-border)',
                                background: 'var(--pwc-orange-light)',
                                color: 'var(--pwc-orange)',
                                boxSizing: 'border-box',
                            }}
                        >
                            {TIME_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                        </select>
                    </div>

                    <div style={{ width: 1, height: 22, background: 'var(--border)', flexShrink: 0 }} />

                    {/* Toggle pill group */}
                    <div style={{ display: 'flex', gap: 3, background: '#F0EFED', borderRadius: 9, padding: '3px 4px', flexShrink: 0 }}>
                        <button
                            onClick={() => setCustomOnly(v => !v)}
                            style={{
                                height: 30, fontSize: 12, paddingInline: 12, borderRadius: 6,
                                border: 'none', cursor: 'pointer', fontWeight: 500,
                                background: customOnly ? '#FFFFFF' : 'transparent',
                                color: customOnly ? 'var(--text-primary)' : 'var(--text-muted)',
                                boxShadow: customOnly ? '0 1px 3px rgba(0,0,0,0.10)' : 'none',
                                transition: 'all 0.15s',
                            }}
                        >
                            Custom only
                        </button>
                        <button
                            onClick={() => setHideEmpty(v => !v)}
                            style={{
                                height: 30, fontSize: 12, paddingInline: 12, borderRadius: 6,
                                border: 'none', cursor: 'pointer', fontWeight: 500,
                                background: hideEmpty ? '#FFFFFF' : 'transparent',
                                color: hideEmpty ? 'var(--text-primary)' : 'var(--text-muted)',
                                boxShadow: hideEmpty ? '0 1px 3px rgba(0,0,0,0.10)' : 'none',
                                transition: 'all 0.15s',
                            }}
                        >
                            Hide empty
                        </button>
                    </div>

                    {/* Refresh */}
                    <button
                        onClick={loadTables}
                        style={{
                            height: 36, fontSize: 12, paddingInline: 14, flexShrink: 0,
                            borderRadius: 8, border: '1px solid var(--border)',
                            background: '#FFFFFF', cursor: 'pointer', color: 'var(--text-secondary)',
                            display: 'flex', alignItems: 'center', gap: 7, fontWeight: 500,
                            boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
                            transition: 'all 0.15s',
                        }}
                    >
                        <FontAwesomeIcon icon={faRefresh} spin={tabLoading} style={{ fontSize: 11 }} />
                        Refresh
                    </button>
                </div>}

                {/* Tables card */}
                {activeSection === 'tables' && <div className="card" style={{ padding: 0, overflow: 'hidden', flexShrink: 0 }}>

                    {/* Card header */}
                    <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <FontAwesomeIcon icon={faDatabase} style={{ fontSize: 11, color: 'var(--text-muted)' }} />
                        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-primary)' }}>
                            Workspace Tables
                        </span>
                        {!tabLoading && tables.length > 0 && (
                            <span className="badge badge-muted" style={{ fontSize: 10 }}>{filtered.length}</span>
                        )}
                    </div>

                    {tabError && (
                        <div style={{ padding: '12px 16px', fontSize: 12, color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: 8 }}>
                            <FontAwesomeIcon icon={faTriangleExclamation} />{tabError}
                        </div>
                    )}

                    {tabLoading && (
                        <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
                            <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 20 }} />
                            <div style={{ marginTop: 8, fontSize: 12 }}>Loading tables…</div>
                        </div>
                    )}

                    {!tabLoading && filtered.length === 0 && !tabError && (
                        <div className="empty-state" style={{ padding: 40 }}>
                            <div className="empty-state-icon">
                                <FontAwesomeIcon icon={faDatabase} style={{ opacity: 0.2, fontSize: 32 }} />
                            </div>
                            <div className="empty-state-text">No tables found</div>
                            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
                                Click Refresh to load workspace tables
                            </div>
                        </div>
                    )}

                    {/* Table rows */}
                    {!tabLoading && filtered.map((table) => {
                        const isExp = expanded === table.DataType;
                        return (
                            <div key={table.DataType} style={{ borderBottom: '1px solid var(--border)' }}>

                                {/* Table header row (clickable) */}
                                <div
                                    onClick={() => openTable(table.DataType)}
                                    style={{
                                        display: 'flex', alignItems: 'center', gap: 12,
                                        padding: '10px 16px', cursor: 'pointer',
                                        borderLeft: isExp ? '3px solid var(--pwc-orange)' : '3px solid transparent',
                                        background: isExp ? 'rgba(208,74,2,0.04)' : undefined,
                                        transition: 'background 0.15s',
                                    }}
                                >
                                    <FontAwesomeIcon
                                        icon={isExp ? faChevronDown : faChevronRight}
                                        style={{ fontSize: 10, color: 'var(--text-muted)', width: 12, flexShrink: 0 }}
                                    />
                                    <FontAwesomeIcon icon={faTable} style={{ fontSize: 11, color: isExp ? 'var(--pwc-orange)' : 'var(--text-muted)', flexShrink: 0 }} />
                                    <span style={{
                                        fontSize: 13, fontWeight: isExp ? 600 : 400,
                                        color: 'var(--text-primary)',
                                        fontFamily: '"JetBrains Mono", Consolas, monospace',
                                        flex: 1,
                                    }}>
                                        {table.DataType}
                                    </span>
                                    {table.Custom && (
                                        <span className="badge badge-low" style={{ fontSize: 9, padding: '2px 6px' }}>
                                            CUSTOM
                                        </span>
                                    )}
                                    <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
                                        {table.Columns != null && (
                                            <span className="badge badge-muted" style={{ fontSize: 10 }}>
                                                {table.Columns} cols
                                            </span>
                                        )}
                                        {table.SizeMB != null ? (
                                            <span className="badge badge-muted" style={{ fontSize: 10 }}>
                                                {Number(table.SizeMB).toLocaleString()} MB
                                            </span>
                                        ) : (
                                            <span className="badge badge-muted" style={{ fontSize: 10, opacity: 0.5 }}>
                                                0 MB
                                            </span>
                                        )}
                                        <button
                                            onClick={e => {
                                                e.stopPropagation();
                                                setExpanded(table.DataType);
                                                setParserOpen(true);
                                                setParserKQL(''); setAlias(''); setNote('');
                                                setRunResult(null); setImplSucc(null); setImplErr(null);
                                                setParserErr(null); setLoadedFromAlias(null);
                                                setParserSteps([]); setChatMessages([]); setChatInput('');
                                                if (wsFunctions.length === 0 && !fnLoading) loadFunctions();
                                                if (expanded !== table.DataType) {
                                                    setLogs(null);
                                                    setGlobSearch(''); setColFilters([]);
                                                    setSortCol('TimeGenerated'); setSortDesc(true);
                                                    setExpRows(new Set());
                                                    fetchLogs(table.DataType, '', [], 'TimeGenerated', true);
                                                }
                                            }}
                                            title="Open AI Parser"
                                            style={{
                                                display: 'flex', alignItems: 'center', gap: 6,
                                                padding: '4px 10px', borderRadius: 6,
                                                border: '1px solid #D04A02',
                                                background: 'rgba(208,74,2,0.07)',
                                                color: '#D04A02', cursor: 'pointer',
                                                fontSize: 11, fontWeight: 600,
                                                whiteSpace: 'nowrap',
                                                transition: 'background 0.15s',
                                            }}
                                            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(208,74,2,0.15)')}
                                            onMouseLeave={e => (e.currentTarget.style.background = 'rgba(208,74,2,0.07)')}
                                        >
                                            <FontAwesomeIcon icon={faRobot} style={{ fontSize: 11 }} />
                                            AI Parser
                                        </button>
                                    </div>
                                </div>

                                {/* Expanded content */}
                                {isExp && (
                                    <div style={{ borderTop: '1px solid var(--border)', padding: 16, background: 'var(--bg-surface)' }}>

                                        {/* ── Filter bar ── */}
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 10, alignItems: 'center' }}>
                                            <div style={{ position: 'relative', flex: '1 1 220px' }}>
                                                <FontAwesomeIcon icon={faSearch} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', fontSize: 10, color: 'var(--text-muted)', pointerEvents: 'none' }} />
                                                <input
                                                    className="form-input"
                                                    placeholder="Search all columns…"
                                                    value={globSearch}
                                                    onChange={e => setGlobSearch(e.target.value)}
                                                    onKeyDown={e => { if (e.key === 'Enter') applySearch(); }}
                                                    style={{ paddingLeft: 28, height: 30, fontSize: 11, width: '100%', boxSizing: 'border-box' }}
                                                />
                                            </div>
                                            <button className="btn btn-ghost btn-sm" onClick={applySearch} style={{ height: 30, fontSize: 11 }}>
                                                <FontAwesomeIcon icon={faSearch} style={{ marginRight: 5 }} />Search
                                            </button>
                                            <button className="btn btn-ghost btn-sm" onClick={() => setAddingF(v => !v)} style={{ height: 30, fontSize: 11 }}>
                                                <FontAwesomeIcon icon={faPlus} style={{ marginRight: 5 }} />Add Filter
                                            </button>
                                            <button className="btn btn-ghost btn-sm" onClick={() => fetchLogs(table.DataType, globSearch, colFilters, sortCol, sortDesc)} style={{ height: 30, fontSize: 11 }}>
                                                <FontAwesomeIcon icon={faRefresh} spin={logsLoading} style={{ marginRight: 5 }} />Reload
                                            </button>
                                        </div>

                                        {/* Add filter form */}
                                        {addingF && logs && (
                                            <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center', padding: '10px 12px', background: 'var(--bg-elevated)', borderRadius: 6, border: '1px solid var(--border)' }}>
                                                <select className="form-select" value={newCol} onChange={e => setNewCol(e.target.value)} style={{ height: 28, fontSize: 11, flex: 1 }}>
                                                    <option value="">Select column…</option>
                                                    {logs.columns.map(c => <option key={c} value={c}>{c}</option>)}
                                                </select>
                                                <input
                                                    className="form-input"
                                                    placeholder="Value…"
                                                    value={newVal}
                                                    onChange={e => setNewVal(e.target.value)}
                                                    onKeyDown={e => { if (e.key === 'Enter') addFilter(); }}
                                                    style={{ height: 28, fontSize: 11, flex: 1 }}
                                                />
                                                <button className="btn btn-primary btn-sm" onClick={addFilter} style={{ height: 28, fontSize: 11 }}>Apply</button>
                                                <button className="btn btn-ghost btn-sm" onClick={() => { setAddingF(false); setNewCol(''); setNewVal(''); }} style={{ height: 28, fontSize: 11 }}>
                                                    <FontAwesomeIcon icon={faXmark} />
                                                </button>
                                            </div>
                                        )}

                                        {/* Active filter chips */}
                                        {colFilters.length > 0 && (
                                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
                                                {colFilters.map((f, i) => (
                                                    <span key={i} className="chip" style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, padding: '3px 8px' }}>
                                                        <FontAwesomeIcon icon={faFilter} style={{ fontSize: 9, color: 'var(--pwc-orange)' }} />
                                                        <span style={{ fontFamily: 'monospace' }}>{f.column}</span>
                                                        <span style={{ color: 'var(--text-muted)' }}>∋</span>
                                                        <span style={{ fontWeight: 600 }}>{f.value}</span>
                                                        <button onClick={() => removeFilter(i)} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '0 0 0 2px', color: 'var(--text-muted)', lineHeight: 1 }}>
                                                            <FontAwesomeIcon icon={faXmark} style={{ fontSize: 9 }} />
                                                        </button>
                                                    </span>
                                                ))}
                                            </div>
                                        )}

                                        {/* Logs loading */}
                                        {logsLoading && (
                                            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>
                                                <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 18 }} />
                                                <div style={{ marginTop: 6, fontSize: 12 }}>Loading logs…</div>
                                            </div>
                                        )}

                                        {/* Logs error */}
                                        {logsError && !logsLoading && (
                                            <div style={{ padding: '10px 14px', color: 'var(--critical)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8, background: 'rgba(192,57,43,0.07)', borderRadius: 6, marginBottom: 10 }}>
                                                <FontAwesomeIcon icon={faTriangleExclamation} />{logsError}
                                            </div>
                                        )}

                                        {/* Logs table */}
                                        {!logsLoading && logs && (
                                            <>
                                                <div style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                                                    <span className="badge badge-info" style={{ fontSize: 10 }}>{logs.row_count.toLocaleString()} rows</span>
                                                    <span className="badge badge-muted" style={{ fontSize: 10 }}>{logs.columns.length} cols</span>
                                                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Click column headers to sort · Click a row to expand</span>
                                                </div>

                                                <div className="data-table-wrap" style={{ maxHeight: 360, overflow: 'auto', borderRadius: 6, border: '1px solid var(--border)' }}>
                                                    <table className="data-table" style={{ fontSize: 11 }}>
                                                        <thead>
                                                            <tr>
                                                                <th style={{ width: 24, padding: '7px 8px' }} />
                                                                {logs.columns.map(col => (
                                                                    <th key={col}
                                                                        onClick={() => handleSort(col)}
                                                                        style={{ cursor: 'pointer', userSelect: 'none', padding: '7px 10px', whiteSpace: 'nowrap' }}
                                                                    >
                                                                        {col}
                                                                        {sortCol === col && (
                                                                            <FontAwesomeIcon
                                                                                icon={sortDesc ? faArrowDown : faArrowUp}
                                                                                style={{ marginLeft: 5, fontSize: 9, color: 'var(--pwc-orange)' }}
                                                                            />
                                                                        )}
                                                                    </th>
                                                                ))}
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {logs.row_count === 0 ? (
                                                                <tr>
                                                                    <td colSpan={logs.columns.length + 1}
                                                                        style={{ padding: '24px', textAlign: 'center', fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                                                                        No logs in the selected time range
                                                                    </td>
                                                                </tr>
                                                            ) : logs.rows.map((row, i) => (
                                                                <Fragment key={i}>
                                                                    <tr onClick={() => toggleRow(i)} style={{ cursor: 'pointer' }}>
                                                                        <td style={{ padding: '6px 8px', textAlign: 'center', color: 'var(--text-muted)' }}>
                                                                            <FontAwesomeIcon icon={expRows.has(i) ? faChevronDown : faChevronRight} style={{ fontSize: 9 }} />
                                                                        </td>
                                                                        {logs.columns.map(col => (
                                                                            <td key={col}
                                                                                title={String(row[col] ?? '')}
                                                                                style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', padding: '6px 10px' }}>
                                                                                {String(row[col] ?? '')}
                                                                            </td>
                                                                        ))}
                                                                    </tr>
                                                                    {expRows.has(i) && (
                                                                        <tr>
                                                                            <td colSpan={logs.columns.length + 1} style={{ padding: '0 8px 10px 32px', background: 'rgba(0,0,0,0.02)' }}>
                                                                                <pre style={{
                                                                                    margin: 0, padding: '10px 12px',
                                                                                    background: '#f6f8fa', color: '#24292e',
                                                                                    border: '1px solid var(--border)',
                                                                                    borderRadius: 6,
                                                                                    fontSize: 10.5,
                                                                                    fontFamily: '"JetBrains Mono", Consolas, monospace',
                                                                                    whiteSpace: 'pre-wrap',
                                                                                    maxHeight: 220, overflow: 'auto',
                                                                                    lineHeight: 1.65,
                                                                                }}>
                                                                                    {JSON.stringify(row, null, 2)}
                                                                                </pre>
                                                                            </td>
                                                                        </tr>
                                                                    )}
                                                                </Fragment>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>

                                            </>
                                        )}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>}

                {/* ── Workspace Functions card ── */}
                {activeSection === 'functions' && (
                    <div className="card" style={{ padding: 0, overflow: 'hidden', flexShrink: 0 }}>

                        {/* Card header */}
                        <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)', display: 'flex', alignItems: 'center', gap: 8 }}>
                            <FontAwesomeIcon icon={faCode} style={{ fontSize: 11, color: 'var(--text-muted)' }} />
                            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-primary)' }}>
                                Workspace Functions
                            </span>
                            {!fnLoading && wsFunctions.length > 0 && (
                                <span className="badge badge-muted" style={{ fontSize: 10 }}>{filteredFns.length}</span>
                            )}
                            <div style={{ flex: 1 }} />
                            {/* Search */}
                            <div style={{ position: 'relative' }}>
                                <FontAwesomeIcon icon={faSearch} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', fontSize: 10, color: 'var(--text-muted)', pointerEvents: 'none' }} />
                                <input
                                    className="form-input"
                                    placeholder="Search functions…"
                                    value={fnSearch}
                                    onChange={e => setFnSearch(e.target.value)}
                                    style={{ paddingLeft: 28, height: 28, fontSize: 11.5, width: 180, boxSizing: 'border-box', borderRadius: 6 }}
                                />
                            </div>
                            <button
                                onClick={loadFunctions}
                                style={{
                                    height: 28, fontSize: 11, paddingInline: 10, flexShrink: 0,
                                    borderRadius: 6, border: '1px solid var(--border)',
                                    background: '#FFFFFF', cursor: 'pointer', color: 'var(--text-secondary)',
                                    display: 'flex', alignItems: 'center', gap: 6, fontWeight: 500,
                                }}
                            >
                                <FontAwesomeIcon icon={faRefresh} spin={fnLoading} style={{ fontSize: 10 }} />
                            </button>
                        </div>

                        {/* Error */}
                        {fnError && (
                            <div style={{ padding: '12px 16px', fontSize: 12, color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: 8 }}>
                                <FontAwesomeIcon icon={faTriangleExclamation} />{fnError}
                            </div>
                        )}

                        {/* Loading */}
                        {fnLoading && (
                            <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
                                <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 20 }} />
                                <div style={{ marginTop: 8, fontSize: 12 }}>Loading functions…</div>
                            </div>
                        )}

                        {/* Empty */}
                        {!fnLoading && filteredFns.length === 0 && !fnError && (
                            <div className="empty-state" style={{ padding: 40 }}>
                                <div className="empty-state-icon">
                                    <FontAwesomeIcon icon={faCode} style={{ opacity: 0.2, fontSize: 32 }} />
                                </div>
                                <div className="empty-state-text">No workspace functions found</div>
                            </div>
                        )}

                        {/* Column headings */}
                        {!fnLoading && filteredFns.length > 0 && (
                            <div style={{
                                display: 'flex', alignItems: 'center', gap: 12,
                                padding: '6px 16px 6px 52px',
                                borderBottom: '1px solid var(--border)',
                                background: 'var(--bg-elevated)',
                            }}>
                                <span style={{ flex: 1, fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                                    Display Name
                                </span>
                                <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', minWidth: 140, textAlign: 'right' }}>
                                    Category
                                </span>
                                <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', minWidth: 120, textAlign: 'right' }}>
                                    Alias
                                </span>
                            </div>
                        )}

                        {/* Function rows */}
                        {!fnLoading && filteredFns.map((fn) => {
                            const isFnExp = expandedFn === fn.id;
                            return (
                                <div key={fn.id} style={{ borderBottom: '1px solid var(--border)' }}>
                                    {/* Row header */}
                                    <div
                                        onClick={() => setExpandedFn(isFnExp ? null : fn.id)}
                                        style={{
                                            display: 'flex', alignItems: 'center', gap: 12,
                                            padding: '10px 16px', cursor: 'pointer',
                                            borderLeft: isFnExp ? '3px solid var(--pwc-orange)' : '3px solid transparent',
                                            background: isFnExp ? 'rgba(208,74,2,0.04)' : undefined,
                                            transition: 'background 0.15s',
                                        }}
                                    >
                                        <FontAwesomeIcon
                                            icon={isFnExp ? faChevronDown : faChevronRight}
                                            style={{ fontSize: 10, color: 'var(--text-muted)', width: 12, flexShrink: 0 }}
                                        />
                                        <FontAwesomeIcon icon={faCode} style={{ fontSize: 11, color: isFnExp ? 'var(--pwc-orange)' : 'var(--text-muted)', flexShrink: 0 }} />
                                        <span style={{
                                            fontSize: 13, fontWeight: isFnExp ? 600 : 400,
                                            color: 'var(--text-primary)',
                                            fontFamily: '"JetBrains Mono", Consolas, monospace',
                                            flex: 1,
                                        }}>
                                            {fn.displayName || fn.alias}
                                        </span>
                                        <span style={{ minWidth: 140, textAlign: 'right', flexShrink: 0 }}>
                                            {fn.category && (
                                                <span className="badge badge-muted" style={{ fontSize: 10 }}>{fn.category}</span>
                                            )}
                                        </span>
                                        <span style={{
                                            fontSize: 11, color: fn.alias ? 'var(--text-secondary)' : 'var(--text-muted)',
                                            fontFamily: 'monospace', minWidth: 120, textAlign: 'right',
                                        }}>
                                            {fn.alias || 'NA'}
                                        </span>
                                    </div>

                                    {/* Expanded details */}
                                    {isFnExp && (
                                        <div style={{ padding: '12px 16px 16px 42px', background: 'rgba(0,0,0,0.015)' }}>
                                            <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
                                                {fn.alias && (
                                                    <span className="badge badge-info" style={{ fontSize: 10 }}>
                                                        alias: {fn.alias}
                                                    </span>
                                                )}
                                                {fn.category && (
                                                    <span className="badge badge-muted" style={{ fontSize: 10 }}>
                                                        {fn.category}
                                                    </span>
                                                )}
                                                {fn.id && (
                                                    <span className="badge badge-muted" style={{ fontSize: 10, fontFamily: 'monospace' }}>
                                                        id: {fn.id}
                                                    </span>
                                                )}
                                            </div>
                                            {fn.query ? (
                                                <pre style={{
                                                    margin: 0, padding: '12px 14px',
                                                    background: '#f6f8fa', color: '#24292e',
                                                    border: '1px solid var(--border)',
                                                    borderRadius: 6,
                                                    fontSize: 11,
                                                    fontFamily: '"JetBrains Mono", Consolas, monospace',
                                                    whiteSpace: 'pre-wrap',
                                                    maxHeight: 280, overflow: 'auto',
                                                    lineHeight: 1.65,
                                                }}>
                                                    {fn.query}
                                                </pre>
                                            ) : (
                                                <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                                                    No query body available
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* ── AI Parser right-side drawer ── */}
            {parserOpen && expanded && (
                <>
                    <style>{`
                        @keyframes drawerSlideIn {
                            from { transform: translateX(100%); opacity: 0; }
                            to   { transform: translateX(0);    opacity: 1; }
                        }
                    `}</style>

                    {/* Backdrop */}
                    <div
                        onClick={() => setParserOpen(false)}
                        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.25)', zIndex: 1099 }}
                    />

                    {/* Drawer panel */}
                    <div style={{
                        position: 'fixed', top: 0, right: 0, bottom: 0, width: drawerWidth,
                        background: '#fff', borderLeft: '1px solid var(--border)',
                        zIndex: 1100, display: 'flex', flexDirection: 'column',
                        boxShadow: '-12px 0 40px rgba(0,0,0,0.14)',
                        animation: 'drawerSlideIn 0.22s ease-out',
                    }}>
                        {/* Drag handle */}
                        <div
                            onMouseDown={onDrawerDragStart}
                            style={{
                                position: 'absolute', left: 0, top: 0, bottom: 0, width: 5,
                                cursor: 'col-resize', zIndex: 10,
                                background: 'transparent',
                                transition: 'background 0.15s',
                            }}
                            onMouseEnter={e => (e.currentTarget.style.background = 'var(--pwc-orange-border)')}
                            onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                        />

                        {/* Drawer header */}
                        <div style={{ padding: '18px 20px 14px', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)', flexShrink: 0 }}>
                            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                                <div style={{ width: 40, height: 40, borderRadius: 10, background: 'linear-gradient(135deg, #D04A02, #b83e00)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                                    <FontAwesomeIcon icon={faRobot} style={{ fontSize: 18, color: '#fff' }} />
                                </div>
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>AI Parser</div>
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{expanded}</div>
                                </div>
                                <button
                                    className="btn btn-ghost btn-sm"
                                    onClick={() => setParserOpen(false)}
                                    style={{ height: 32, width: 32, padding: 0, flexShrink: 0, borderRadius: 8 }}
                                >
                                    <FontAwesomeIcon icon={faXmark} style={{ fontSize: 13 }} />
                                </button>
                            </div>
                        </div>

                        {/* Drawer body */}
                        <div style={{ flex: 1, overflow: 'auto', padding: '20px', display: 'flex', flexDirection: 'column', gap: 14 }}>

                            {/* Generate button — only shown before any run has started */}
                            {!creating && parserSteps.length === 0 && !parserKQL && (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

                                    {/* ── Related parsers ── */}
                                    {(fnLoading || relatedParsers.length > 0) && (
                                        <div style={{ border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden' }}>
                                            <div style={{
                                                padding: '9px 14px', background: 'var(--bg-elevated)',
                                                borderBottom: relatedParsers.length > 0 ? '1px solid var(--border)' : 'none',
                                                display: 'flex', alignItems: 'center', gap: 8,
                                            }}>
                                                <FontAwesomeIcon icon={faFolderOpen} style={{ fontSize: 11, color: 'var(--pwc-orange)' }} />
                                                <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-primary)', flex: 1 }}>
                                                    Related Parsers in Workspace
                                                </span>
                                                {fnLoading && <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 10, color: 'var(--text-muted)' }} />}
                                                {relatedParsers.length > 0 && (
                                                    <span className="badge badge-muted" style={{ fontSize: 10 }}>{relatedParsers.length}</span>
                                                )}
                                            </div>
                                            {relatedParsers.map(fn => (
                                                <div key={fn.id} style={{
                                                    padding: '10px 14px',
                                                    borderBottom: '1px solid var(--border)',
                                                    display: 'flex', flexDirection: 'column', gap: 6,
                                                }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                                                        <FontAwesomeIcon icon={faCode} style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 }} />
                                                        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                            {fn.displayName || fn.alias}
                                                        </span>
                                                        {fn.category && (
                                                            <span className="badge badge-muted" style={{ fontSize: 9 }}>{fn.category}</span>
                                                        )}
                                                    </div>
                                                    {fn.query && (
                                                        <pre style={{
                                                            margin: 0, padding: '6px 10px',
                                                            background: '#f6f8fa', border: '1px solid var(--border)', borderRadius: 5,
                                                            fontSize: 10.5, fontFamily: '"JetBrains Mono", Consolas, monospace',
                                                            whiteSpace: 'pre-wrap', color: '#4b5563', lineHeight: 1.55,
                                                            maxHeight: 60, overflow: 'hidden',
                                                        }}>
                                                            {fn.query.split('\n').slice(0, 3).join('\n')}
                                                        </pre>
                                                    )}
                                                    <div style={{ display: 'flex', gap: 7 }}>
                                                        <button
                                                            onClick={() => loadExistingParser(fn)}
                                                            style={{
                                                                display: 'flex', alignItems: 'center', gap: 6,
                                                                padding: '4px 10px', borderRadius: 6,
                                                                border: '1px solid var(--pwc-orange)',
                                                                background: 'rgba(208,74,2,0.07)',
                                                                color: 'var(--pwc-orange)',
                                                                fontSize: 11, fontWeight: 600, cursor: 'pointer',
                                                                transition: 'background 0.15s',
                                                            }}
                                                            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(208,74,2,0.15)')}
                                                            onMouseLeave={e => (e.currentTarget.style.background = 'rgba(208,74,2,0.07)')}
                                                        >
                                                            <FontAwesomeIcon icon={faFolderOpen} style={{ fontSize: 10 }} />
                                                            Load &amp; Edit
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}

                                    <div style={{ padding: '14px 16px', background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.18)', borderRadius: 10, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                                        <FontAwesomeIcon icon={faCircleInfo} style={{ color: 'var(--info)', marginRight: 7 }} />
                                        AI will sample up to <strong>{logs ? Math.min(10, logs.row_count) : 0} rows</strong> from <code style={{ fontFamily: 'monospace' }}>{expanded}</code>, analyse the log structure, generate a KQL parser, run it, and auto-fix any errors — all automatically.
                                    </div>

                                    {/* Custom parser request chat input */}
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)' }}>
                                            Describe what you want to parse <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>(optional)</span>
                                        </span>
                                        <div style={{ display: 'flex', gap: 8 }}>
                                            <input
                                                className="form-input"
                                                placeholder='e.g. "Extract IP addresses and map severity from Properties JSON"'
                                                value={parserRequest}
                                                onChange={e => setParserRequest(e.target.value)}
                                                onKeyDown={e => {
                                                    if (e.key === 'Enter' && parserRequest.trim() && logs && logs.row_count > 0) {
                                                        parserRun(parserRequest.trim());
                                                    }
                                                }}
                                                disabled={!logs || logs.row_count === 0}
                                                style={{ flex: 1, height: 36, fontSize: 12, boxSizing: 'border-box' }}
                                            />
                                            <button
                                                onClick={() => parserRun(parserRequest.trim() || undefined)}
                                                disabled={!parserRequest.trim() || !logs || logs.row_count === 0}
                                                title="Send request"
                                                style={{
                                                    height: 36, width: 36, borderRadius: 8, flexShrink: 0,
                                                    border: 'none',
                                                    cursor: parserRequest.trim() && logs && logs.row_count > 0 ? 'pointer' : 'not-allowed',
                                                    background: parserRequest.trim() && logs && logs.row_count > 0 ? '#D04A02' : 'var(--border)',
                                                    color: '#fff',
                                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                    transition: 'background 0.15s',
                                                }}
                                            >
                                                <FontAwesomeIcon icon={faPaperPlane} style={{ fontSize: 12 }} />
                                            </button>
                                        </div>
                                        {[
                                            'Parse JSON in Properties field',
                                            'Extract IPs and map to ASIM',
                                            'Normalise severity to ASIM EventSeverity',
                                        ].map(s => (
                                            <button
                                                key={s}
                                                onClick={() => setParserRequest(s)}
                                                style={{
                                                    alignSelf: 'flex-start',
                                                    padding: '3px 10px', borderRadius: 20,
                                                    border: '1px solid var(--border)',
                                                    background: 'var(--bg-elevated)',
                                                    fontSize: 11, cursor: 'pointer',
                                                    color: 'var(--text-secondary)',
                                                    transition: 'all 0.15s',
                                                }}
                                                onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--pwc-orange)'; e.currentTarget.style.color = 'var(--pwc-orange)'; }}
                                                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-secondary)'; }}
                                            >
                                                {s}
                                            </button>
                                        ))}
                                    </div>

                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                        <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                                        <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>or auto-generate</span>
                                        <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                                    </div>

                                    <button
                                        className="btn btn-primary"
                                        disabled={!logs || logs.row_count === 0}
                                        onClick={() => parserRun()}
                                        style={{ padding: '12px 20px', fontSize: 13, borderRadius: 8 }}
                                    >
                                        <FontAwesomeIcon icon={faRobot} style={{ marginRight: 10 }} />Generate &amp; Run Parser
                                    </button>
                                </div>
                            )}

                            {/* ── Thinking panel ── */}
                            {(parserSteps.length > 0 || creating) && (
                                <div style={{
                                    padding: '14px 16px',
                                    background: '#f8f9fb',
                                    border: '1px solid #e5e7eb',
                                    borderRadius: 10,
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: 10,
                                }}>
                                    <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: '#6b7280', marginBottom: 2, display: 'flex', alignItems: 'center', gap: 7 }}>
                                        <FontAwesomeIcon icon={faRobot} style={{ fontSize: 10 }} />
                                        AI Reasoning
                                    </div>

                                    {/* Placeholder pulse when SSE just started */}
                                    {creating && parserSteps.length === 0 && (
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                                            <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 11, color: '#f97316', flexShrink: 0 }} />
                                            <span style={{ fontSize: 12, color: '#f97316' }}>Initialising…</span>
                                        </div>
                                    )}

                                    {parserSteps.map((step, i) => {
                                        const isFix = step.label.toLowerCase().includes('fix') || step.label.toLowerCase().includes('diagnos');
                                        return (
                                            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 9 }}>
                                                <div style={{ width: 16, flexShrink: 0, paddingTop: 1 }}>
                                                    {step.status === 'running' && <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 11, color: '#f97316' }} />}
                                                    {step.status === 'done' && <FontAwesomeIcon icon={faCheckCircle} style={{ fontSize: 11, color: '#22c55e' }} />}
                                                    {step.status === 'error' && <FontAwesomeIcon icon={faTriangleExclamation} style={{ fontSize: 11, color: '#ef4444' }} />}
                                                </div>
                                                <div style={{ flex: 1, minWidth: 0 }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                        {isFix && <FontAwesomeIcon icon={faWrench} style={{ fontSize: 9, color: '#9ca3af', flexShrink: 0 }} />}
                                                        <span style={{
                                                            fontSize: 12, lineHeight: 1.4,
                                                            color: step.status === 'done' ? '#374151'
                                                                : step.status === 'error' ? '#ef4444'
                                                                    : '#f97316',
                                                        }}>
                                                            {step.label}
                                                        </span>
                                                    </div>
                                                    {step.detail && (
                                                        <div style={{ fontSize: 10.5, color: '#6b7280', marginTop: 3, fontFamily: '"JetBrains Mono", Consolas, monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                                            {step.detail}
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}

                            {/* Error banner (shown after run completes with failure) */}
                            {parserErr && !creating && (
                                <div style={{ padding: '10px 14px', background: 'rgba(192,57,43,0.07)', border: '1px solid rgba(192,57,43,0.25)', borderRadius: 8, fontSize: 12, color: 'var(--critical)', display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                                    <FontAwesomeIcon icon={faTriangleExclamation} style={{ flexShrink: 0, marginTop: 1 }} />
                                    <span style={{ wordBreak: 'break-word' }}>{parserErr}</span>
                                </div>
                            )}

                            {/* Parser note — what was parsed */}
                            {parserNote && !creating && (
                                <div style={{ padding: '10px 14px', background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 8, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.65 }}>
                                    <FontAwesomeIcon icon={faCircleInfo} style={{ color: 'var(--info)', marginRight: 7, flexShrink: 0 }} />
                                    {parserNote}
                                </div>
                            )}

                            {/* KQL editor + actions */}
                            {parserKQL && (
                                <>
                                    <div>
                                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                                            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-primary)' }}>
                                                Parser KQL
                                            </span>
                                            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                                                alias: <strong>{parserAlias}</strong>
                                            </span>
                                        </div>
                                        {loadedFromAlias && (
                                            <div style={{
                                                display: 'flex', alignItems: 'center', gap: 7,
                                                padding: '6px 10px', marginBottom: 8,
                                                background: 'rgba(208,74,2,0.06)',
                                                border: '1px solid rgba(208,74,2,0.22)',
                                                borderRadius: 6, fontSize: 11, color: 'var(--pwc-orange)',
                                            }}>
                                                <FontAwesomeIcon icon={faFolderOpen} style={{ fontSize: 10 }} />
                                                Editing existing parser: <strong style={{ fontFamily: 'monospace', marginLeft: 3 }}>{loadedFromAlias}</strong>
                                            </div>
                                        )}
                                        <textarea
                                            className="form-textarea mono"
                                            value={parserKQL}
                                            onChange={e => setParserKQL(e.target.value)}
                                            rows={14}
                                            style={{ width: '100%', resize: 'vertical', boxSizing: 'border-box', fontSize: 11.5, lineHeight: 1.7, background: 'var(--bg-deep, #f8fafc)', borderRadius: 8 }}
                                        />
                                    </div>

                                    {/* Action row */}
                                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                                        <button className="btn btn-ghost btn-sm" disabled={creating} onClick={() => parserRun()} style={{ fontSize: 12 }}>
                                            <FontAwesomeIcon icon={faRobot} style={{ marginRight: 6 }} />
                                            {creating ? 'Regenerating…' : 'Regenerate'}
                                        </button>
                                        <button className="btn btn-primary btn-sm" disabled={running || creating} onClick={runParser} style={{ fontSize: 12 }}>
                                            {running
                                                ? <><FontAwesomeIcon icon={faSpinner} spin style={{ marginRight: 6 }} />Running…</>
                                                : <><FontAwesomeIcon icon={faPlay} style={{ marginRight: 6 }} />Run Parser</>}
                                        </button>
                                    </div>

                                    {/* Parser output */}
                                    {runResult && (
                                        <div>
                                            <div style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                                                <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Parser Output</span>
                                                <span className="badge badge-info" style={{ fontSize: 10 }}>{runResult.row_count} rows</span>
                                                <span className="badge badge-muted" style={{ fontSize: 10 }}>{runResult.columns.length} cols</span>
                                            </div>
                                            {runResult.row_count === 0 ? (
                                                <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '10px 0', fontStyle: 'italic' }}>Parser returned no rows</div>
                                            ) : (
                                                <div className="data-table-wrap" style={{ maxHeight: 320, overflow: 'auto', borderRadius: 8, border: '1px solid var(--border)' }}>
                                                    <table className="data-table" style={{ fontSize: 11 }}>
                                                        <thead>
                                                            <tr>
                                                                <th style={{ padding: '7px 8px', width: 24 }} />
                                                                {runResult.columns.map(c => <th key={c} style={{ padding: '7px 10px' }}>{c}</th>)}
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {runResult.rows.map((row, i) => (
                                                                <Fragment key={i}>
                                                                    <tr onClick={() => toggleRunRow(i)} style={{ cursor: 'pointer' }}>
                                                                        <td style={{ padding: '6px 8px', textAlign: 'center', color: 'var(--text-muted)' }}>
                                                                            <FontAwesomeIcon icon={expRunRows.has(i) ? faChevronDown : faChevronRight} style={{ fontSize: 9 }} />
                                                                        </td>
                                                                        {runResult.columns.map(c => (
                                                                            <td key={c} title={String(row[c] ?? '')}
                                                                                style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', padding: '6px 10px' }}>
                                                                                {String(row[c] ?? '')}
                                                                            </td>
                                                                        ))}
                                                                    </tr>
                                                                    {expRunRows.has(i) && (
                                                                        <tr>
                                                                            <td colSpan={runResult.columns.length + 1} style={{ padding: '0 8px 10px 32px', background: 'rgba(0,0,0,0.02)' }}>
                                                                                <pre style={{
                                                                                    margin: 0, padding: '10px 12px',
                                                                                    background: '#f6f8fa', color: '#24292e',
                                                                                    border: '1px solid var(--border)',
                                                                                    borderRadius: 6, fontSize: 10.5,
                                                                                    fontFamily: '"JetBrains Mono", Consolas, monospace',
                                                                                    whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                                                                    maxHeight: 260, overflow: 'auto', lineHeight: 1.65,
                                                                                }}>
                                                                                    {JSON.stringify(row, null, 2)}
                                                                                </pre>
                                                                            </td>
                                                                        </tr>
                                                                    )}
                                                                </Fragment>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </>
                            )}

                            {/* ── Chat refine section ── */}
                            {parserKQL && (
                                <div style={{ borderTop: '1px solid var(--border)', paddingTop: 16 }}>
                                    <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-primary)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 7 }}>
                                        <FontAwesomeIcon icon={faRobot} style={{ fontSize: 11, color: 'var(--pwc-orange)' }} />
                                        Refine with Chat
                                    </div>

                                    {/* Suggested prompts — shown only when no messages yet */}
                                    {chatMessages.length === 0 && (
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
                                            {[
                                                'Parse the JSON in the Properties field',
                                                'Extract IP addresses and map to ASIM',
                                                'Add EventResult Success/Failure mapping',
                                                'Explain what this parser extracts',
                                            ].map(suggestion => (
                                                <button
                                                    key={suggestion}
                                                    onClick={() => { setChatInput(suggestion); }}
                                                    style={{
                                                        padding: '4px 10px', borderRadius: 20,
                                                        border: '1px solid var(--border)',
                                                        background: 'var(--bg-elevated)',
                                                        fontSize: 11, cursor: 'pointer',
                                                        color: 'var(--text-secondary)',
                                                        transition: 'all 0.15s',
                                                    }}
                                                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--pwc-orange)'; e.currentTarget.style.color = 'var(--pwc-orange)'; }}
                                                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-secondary)'; }}
                                                >
                                                    {suggestion}
                                                </button>
                                            ))}
                                        </div>
                                    )}

                                    {/* Message history */}
                                    {chatMessages.length > 0 && (
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 10, maxHeight: 300, overflowY: 'auto' }}>
                                            {chatMessages.map((msg, i) => (
                                                <div key={i} style={{
                                                    padding: '8px 12px', borderRadius: 8,
                                                    fontSize: 12, lineHeight: 1.65,
                                                    background: msg.role === 'user' ? 'rgba(208,74,2,0.07)' : '#f8f9fb',
                                                    border: `1px solid ${msg.role === 'user' ? 'rgba(208,74,2,0.2)' : '#e5e7eb'}`,
                                                    alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
                                                    maxWidth: '92%',
                                                    color: 'var(--text-primary)',
                                                    whiteSpace: 'pre-wrap',
                                                    wordBreak: 'break-word',
                                                }}>
                                                    {msg.role === 'assistant' && (
                                                        <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--pwc-orange)', display: 'block', marginBottom: 3 }}>AI</span>
                                                    )}
                                                    {msg.content}
                                                </div>
                                            ))}
                                            {chatLoading && (
                                                <div style={{ padding: '8px 12px', borderRadius: 8, fontSize: 12, background: '#f8f9fb', border: '1px solid #e5e7eb', alignSelf: 'flex-start', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 7 }}>
                                                    <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 10 }} />
                                                    Thinking…
                                                </div>
                                            )}
                                            <div ref={chatEndRef} />
                                        </div>
                                    )}

                                    {/* Input row */}
                                    <div style={{ display: 'flex', gap: 8 }}>
                                        <input
                                            className="form-input"
                                            placeholder='e.g. "Parse the IP from Properties JSON"'
                                            value={chatInput}
                                            onChange={e => setChatInput(e.target.value)}
                                            onKeyDown={e => { if (e.key === 'Enter' && !chatLoading) sendChat(); }}
                                            disabled={chatLoading}
                                            style={{ flex: 1, height: 36, fontSize: 12, boxSizing: 'border-box' }}
                                        />
                                        <button
                                            onClick={sendChat}
                                            disabled={chatLoading || !chatInput.trim()}
                                            style={{
                                                height: 36, width: 36, borderRadius: 8, flexShrink: 0,
                                                border: 'none', cursor: chatInput.trim() && !chatLoading ? 'pointer' : 'not-allowed',
                                                background: chatInput.trim() && !chatLoading ? '#D04A02' : 'var(--border)',
                                                color: '#fff',
                                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                transition: 'background 0.15s',
                                            }}
                                        >
                                            <FontAwesomeIcon icon={chatLoading ? faSpinner : faPaperPlane} spin={chatLoading} style={{ fontSize: 12 }} />
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Drawer footer — Implement button */}
                        {parserKQL && (
                            <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border)', background: 'var(--bg-elevated)', flexShrink: 0 }}>
                                {implSuccess ? (
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#059669', fontWeight: 600 }}>
                                        <FontAwesomeIcon icon={faCheckCircle} style={{ fontSize: 16 }} />
                                        Saved as workspace function <code style={{ fontFamily: 'monospace', marginLeft: 4 }}>{implSuccess}</code>
                                    </div>
                                ) : (
                                    <button
                                        className="btn btn-primary"
                                        disabled={creating || running || !parserValid}
                                        onClick={openSaveModal}
                                        title={!parserValid ? 'Run the parser successfully before implementing' : undefined}
                                        style={{ width: '100%', padding: '12px', fontSize: 13, borderRadius: 8, background: parserValid ? '#059669' : 'var(--text-muted)', borderColor: parserValid ? '#059669' : 'var(--text-muted)', cursor: parserValid ? 'pointer' : 'not-allowed' }}
                                    >
                                        <FontAwesomeIcon icon={faCode} style={{ marginRight: 10 }} />Implement as Workspace Function
                                    </button>
                                )}
                            </div>
                        )}
                    </div>
                </>
            )}

            {/* ── Save as Function modal ── */}
            {saveModal && parserKQL && (
                <>
                    <div
                        onClick={() => setSaveModal(false)}
                        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)', zIndex: 1200 }}
                    />
                    <div style={{
                        position: 'fixed', top: '50%', left: '50%',
                        transform: 'translate(-50%, -50%)',
                        width: 540, maxHeight: '88vh',
                        background: '#fff', borderRadius: 12,
                        boxShadow: '0 24px 64px rgba(0,0,0,0.22)',
                        zIndex: 1201, display: 'flex', flexDirection: 'column',
                        overflow: 'hidden',
                    }}>
                        {/* Modal header */}
                        <div style={{ padding: '18px 22px 14px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
                            <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>Save as function</span>
                            <button onClick={() => setSaveModal(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}>
                                <FontAwesomeIcon icon={faXmark} style={{ fontSize: 14 }} />
                            </button>
                        </div>

                        {/* Modal body */}
                        <div style={{ flex: 1, overflow: 'auto', padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 16 }}>

                            {/* Function name */}
                            <div>
                                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 6 }}>
                                    Function name <span style={{ color: 'var(--critical)' }}>*</span>
                                </label>
                                <input
                                    className="form-input"
                                    value={saveName}
                                    onChange={e => setSaveName(e.target.value.replace(/[^A-Za-z0-9_\-]/g, ''))}
                                    placeholder="e.g. parse_aad_audit_logs"
                                    style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 12 }}
                                />
                                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 4 }}>
                                    Letters, numbers, underscores and hyphens only. This becomes the callable function alias.
                                </div>
                            </div>

                            {/* Code preview */}
                            <div>
                                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 6 }}>Code</label>
                                <pre style={{
                                    margin: 0, padding: '10px 13px',
                                    background: '#f6f8fa', border: '1px solid var(--border)', borderRadius: 6,
                                    fontSize: 11, fontFamily: '"JetBrains Mono", Consolas, monospace',
                                    whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                                    maxHeight: 160, overflow: 'auto',
                                    color: 'var(--text-secondary)', lineHeight: 1.6,
                                }}>
                                    {parserKQL}
                                </pre>
                            </div>

                            {/* Legacy category */}
                            <div>
                                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 6 }}>
                                    Legacy category <span style={{ color: 'var(--critical)' }}>*</span>
                                </label>
                                <input
                                    className="form-input"
                                    value={saveCategory}
                                    onChange={e => setSaveCategory(e.target.value)}
                                    placeholder="e.g. Parser"
                                    style={{ width: '100%', boxSizing: 'border-box', fontSize: 12 }}
                                />
                            </div>

                            {/* Function parameters */}
                            <div>
                                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 10 }}>
                                    Function parameters
                                </label>

                                {saveParams.length > 0 && (
                                    <div style={{ marginBottom: 8 }}>
                                        {/* Header row */}
                                        <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr 1fr 28px', gap: 8, marginBottom: 6 }}>
                                            {['Type', 'Name', 'Default value', ''].map(h => (
                                                <span key={h} style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{h}</span>
                                            ))}
                                        </div>
                                        {saveParams.map((p, i) => (
                                            <div key={i} style={{ display: 'grid', gridTemplateColumns: '140px 1fr 1fr 28px', gap: 8, marginBottom: 6, alignItems: 'center' }}>
                                                <select
                                                    className="form-select"
                                                    value={p.type}
                                                    onChange={e => setSaveParams(prev => prev.map((x, j) => j === i ? { ...x, type: e.target.value } : x))}
                                                    style={{ height: 32, fontSize: 12 }}
                                                >
                                                    {KQL_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                                                </select>
                                                <input
                                                    className="form-input"
                                                    value={p.name}
                                                    onChange={e => setSaveParams(prev => prev.map((x, j) => j === i ? { ...x, name: e.target.value } : x))}
                                                    placeholder="param_name"
                                                    style={{ height: 32, fontSize: 12, fontFamily: 'monospace' }}
                                                />
                                                <input
                                                    className="form-input"
                                                    value={p.defaultValue}
                                                    onChange={e => setSaveParams(prev => prev.map((x, j) => j === i ? { ...x, defaultValue: e.target.value } : x))}
                                                    placeholder="default value"
                                                    style={{ height: 32, fontSize: 12 }}
                                                />
                                                <button
                                                    onClick={() => setSaveParams(prev => prev.filter((_, j) => j !== i))}
                                                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                                                >
                                                    <FontAwesomeIcon icon={faXmark} style={{ fontSize: 12 }} />
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                )}

                                <button
                                    onClick={() => setSaveParams(prev => [...prev, { type: 'string', name: '', defaultValue: '' }])}
                                    style={{ background: 'none', border: '1px dashed var(--border)', borderRadius: 6, padding: '6px 12px', fontSize: 12, color: 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}
                                >
                                    <FontAwesomeIcon icon={faPlus} style={{ fontSize: 10 }} />
                                    Add parameter
                                </button>
                            </div>

                            {/* Error */}
                            {implError && (
                                <div style={{ padding: '10px 13px', background: 'rgba(192,57,43,0.07)', border: '1px solid rgba(192,57,43,0.25)', borderRadius: 8, fontSize: 12, color: 'var(--critical)', display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                                    <FontAwesomeIcon icon={faTriangleExclamation} style={{ flexShrink: 0, marginTop: 1 }} />{implError}
                                </div>
                            )}
                        </div>

                        {/* Modal footer */}
                        <div style={{ padding: '14px 22px', borderTop: '1px solid var(--border)', background: 'var(--bg-elevated)', flexShrink: 0, display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                            <button className="btn btn-ghost" onClick={() => setSaveModal(false)} style={{ fontSize: 13 }}>
                                Cancel
                            </button>
                            <button
                                className="btn btn-primary"
                                disabled={implementing || !saveName.trim()}
                                onClick={implementParser}
                                style={{ fontSize: 13, background: '#059669', borderColor: '#059669', minWidth: 110 }}
                            >
                                {implementing
                                    ? <><FontAwesomeIcon icon={faSpinner} spin style={{ marginRight: 8 }} />Saving…</>
                                    : <><FontAwesomeIcon icon={faCheckCircle} style={{ marginRight: 8 }} />Save</>}
                            </button>
                        </div>
                    </div>
                </>
            )}
        </div>
    );
}
