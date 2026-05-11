import { useState, useEffect, useMemo } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { RadialBarChart, RadialBar, ResponsiveContainer, PolarAngleAxis } from 'recharts';
import {
    faShieldHalved, faFileLines, faCircleCheck, faFire, faClipboardList,
    faThumbtack, faArrowLeft, faCheck, faXmark, faFilePdf, faFileCode,
    faListCheck, faTriangleExclamation, faBullseye, faComment,
    faMagnifyingGlass, faDatabase, faExclamationCircle,
} from '@fortawesome/free-solid-svg-icons';

// ── Types ─────────────────────────────────────────────────────────────────────
interface Technique {
    id: string;
    name: string;
    covered: boolean;
    score: number;
}
interface Tactic {
    id: string;
    name: string;
    coverage: number;
    incidents: number;
    techniques_total: number;
    techniques_covered: number;
    techniques_list: Technique[];
}
interface Rule {
    id: number;
    tactic: string;
    tactic_name: string;
    technique: string;
    technique_name: string;
    priority: string;
    description: string;
    detection_method: string;
    mitre_data_source: string;
    rule_template: string;
    estimated_incidents: number;
    implementation_effort: string;
}
interface MissingLogSource {
    id: number;
    source_name: string;
    category: string;
    status: string;
    priority: string;
    sentinel_table: string;
    tactics_affected: string[];
    techniques_covered: string[];
    technique_count: number;
    description: string;
    implementation: string;
    estimated_coverage_gain: number;
}
interface MitreData {
    tactics?: Tactic[];
    recommended_rules?: Rule[];
    missing_log_sources?: MissingLogSource[];
    summary?: {
        overall_coverage: number;
        assessment: string;
        total_tactics: number;
        tactics_with_coverage: number;
        total_techniques: number;
        covered_techniques: number;
        total_incidents: number;
    };
}

interface UseCase {
    id: string;
    name: string;
    kind: string;
    enabled: boolean;
    severity: string;
    tactics: string[];
    techniques: string[];
    description: string;
    last_modified: string;
    query_frequency: string;
    template_name: string;
}
interface UseCasesData {
    rules: UseCase[];
    by_tactic: Record<string, { total: number; enabled: number; disabled: number; rules: UseCase[] }>;
    summary: { total: number; enabled: number; disabled: number; by_kind: Record<string, number> };
    error?: string;
}

interface FpData {
    summary: {
        total: number;
        true_positive: number;
        false_positive: number;
        benign_positive: number;
        undetermined: number;
        unclassified: number;
        fp_rate: number;
        tp_rate: number;
    };
    top_fp_rules: Array<{ title: string; severity: string; fp_count: number; avg_mttr_hours: number }>;
    fine_tuning_comments: Array<{
        incident_number: string;
        title: string;
        severity: string;
        classification: string;
        comment: string;
        comment_time: string;
    }>;
}

interface TechniqueHit {
    id: string;
    tactics: string;
    alert_count: number;
    unique_rules: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    last_seen: string;
}

type TabId = 'heatmap' | 'tactics' | 'rules' | 'use-cases' | 'false-positives' | 'technique-activity' | 'log-sources';

// ── Helpers ───────────────────────────────────────────────────────────────────
function coverageColor(pct: number): string {
    if (pct === 0) return '#C0392B';
    if (pct < 30) return '#E74C3C';
    if (pct < 50) return '#E67E22';
    if (pct < 70) return '#D4AC0D';
    if (pct < 85) return '#27AE60';
    return '#1E8449';
}
function coverageBg(pct: number): string {
    if (pct === 0) return 'rgba(192,57,43,0.08)';
    if (pct < 30) return 'rgba(231,76,60,0.08)';
    if (pct < 50) return 'rgba(230,126,34,0.08)';
    if (pct < 70) return 'rgba(212,172,13,0.08)';
    return 'rgba(39,174,96,0.08)';
}
function riskBadge(pct: number) {
    if (pct < 30) return 'badge-critical';
    if (pct < 50) return 'badge-high';
    if (pct < 70) return 'badge-medium';
    return 'badge-low';
}
function priorityBadge(p: string) {
    const m: Record<string, string> = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', LOW: 'badge-low' };
    return m[p.toUpperCase()] || 'badge-muted';
}
function severityBadge(s: string) {
    const m: Record<string, string> = { High: 'badge-high', Medium: 'badge-medium', Low: 'badge-low', Informational: 'badge-muted' };
    return m[s] || 'badge-muted';
}
function relativeTime(iso: string): string {
    if (!iso) return '—';
    const diff = Date.now() - new Date(iso).getTime();
    const h = Math.floor(diff / 3_600_000);
    if (h < 1) return '<1h ago';
    if (h < 24) return `${h}h ago`;
    const d = Math.floor(h / 24);
    if (d < 30) return `${d}d ago`;
    return `${Math.floor(d / 30)}mo ago`;
}
function formatHours(h: number): string {
    if (!h) return '—';
    if (h < 1) return `${Math.round(h * 60)}m`;
    if (h < 48) return `${h.toFixed(1)}h`;
    return `${(h / 24).toFixed(1)}d`;
}

function ProgressBar({ pct, height = 6, color }: { pct: number; height?: number; color?: string }) {
    const fillClass = color
        ? ''
        : pct < 30 ? 'red' : pct < 60 ? 'yellow' : 'green';
    return (
        <div className="progress-bar-wrap" style={{ height }}>
            <div
                className={`progress-bar-fill ${fillClass}`}
                style={{ width: `${Math.min(pct, 100)}%`, ...(color ? { background: color } : {}) }}
            />
        </div>
    );
}

function LoadingPane() {
    return (
        <div style={{ padding: 60, textAlign: 'center' }}>
            <div className="spinner spinner-lg" style={{ margin: '0 auto 12px' }} />
            <div className="text-muted">Loading data…</div>
        </div>
    );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function MitreCoverage() {
    const [data, setData] = useState<MitreData>({});
    const [loading, setLoading] = useState(true);
    const [generating, setGenerating] = useState(false);
    const [genResult, setGenResult] = useState<{ generated?: { name: string; type: string }[]; message?: string } | null>(null);
    const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
    const [tab, setTab] = useState<TabId>('heatmap');

    // Use Cases
    const [useCases, setUseCases] = useState<UseCasesData | null>(null);
    const [ucLoading, setUcLoading] = useState(false);
    const [ucSearch, setUcSearch] = useState('');
    const [ucTacticFilter, setUcTacticFilter] = useState('All');
    const [ucStatusFilter, setUcStatusFilter] = useState<'All' | 'Enabled' | 'Disabled'>('All');
    const [ucKindFilter, setUcKindFilter] = useState('All');

    // False Positives
    const [fpData, setFpData] = useState<FpData | null>(null);
    const [fpLoading, setFpLoading] = useState(false);

    // Technique Activity
    const [techHits, setTechHits] = useState<TechniqueHit[]>([]);
    const [techLoading, setTechLoading] = useState(false);

    const [loadedTabs, setLoadedTabs] = useState<Set<string>>(new Set());

    useEffect(() => {
        axios.get('/api/mitre/data').then(r => setData(r.data)).finally(() => setLoading(false));
    }, []);

    useEffect(() => {
        const mark = (t: string) => setLoadedTabs(prev => new Set([...prev, t]));
        if (tab === 'use-cases' && !loadedTabs.has('use-cases')) {
            setUcLoading(true);
            axios.get('/api/mitre/use-cases')
                .then(r => setUseCases(r.data))
                .catch(() => setUseCases({ rules: [], by_tactic: {}, summary: { total: 0, enabled: 0, disabled: 0, by_kind: {} } }))
                .finally(() => { setUcLoading(false); mark('use-cases'); });
        }
        if (tab === 'false-positives' && !loadedTabs.has('false-positives')) {
            setFpLoading(true);
            axios.get('/api/mitre/false-positives')
                .then(r => setFpData(r.data))
                .catch(() => setFpData(null))
                .finally(() => { setFpLoading(false); mark('false-positives'); });
        }
        if (tab === 'technique-activity' && !loadedTabs.has('technique-activity')) {
            setTechLoading(true);
            axios.get('/api/mitre/technique-activity')
                .then(r => setTechHits(r.data.techniques || []))
                .catch(() => setTechHits([]))
                .finally(() => { setTechLoading(false); mark('technique-activity'); });
        }
    }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps

    const selected = useMemo(
        () => data.tactics?.find(t => t.id === selectedTactic),
        [data.tactics, selectedTactic]
    );

    const filteredUC = useMemo(() => {
        if (!useCases) return [];
        return useCases.rules.filter(uc => {
            const q = ucSearch.toLowerCase();
            const matchSearch = !q || uc.name.toLowerCase().includes(q)
                || uc.techniques.some(t => t.toLowerCase().includes(q));
            const matchTactic = ucTacticFilter === 'All' || uc.tactics.includes(ucTacticFilter);
            const matchStatus = ucStatusFilter === 'All'
                || (ucStatusFilter === 'Enabled' && uc.enabled)
                || (ucStatusFilter === 'Disabled' && !uc.enabled);
            const matchKind = ucKindFilter === 'All' || uc.kind === ucKindFilter;
            return matchSearch && matchTactic && matchStatus && matchKind;
        });
    }, [useCases, ucSearch, ucTacticFilter, ucStatusFilter, ucKindFilter]);

    const ucTactics = useMemo(() => {
        if (!useCases) return [];
        return Object.keys(useCases.by_tactic).sort();
    }, [useCases]);

    const ucKinds = useMemo(() => {
        if (!useCases) return [];
        return Object.keys(useCases.summary.by_kind || {}).sort();
    }, [useCases]);

    const maxTechCount = useMemo(() => Math.max(...techHits.map(t => t.alert_count), 1), [techHits]);

    const handleGenerate = async () => {
        setGenerating(true);
        setGenResult(null);
        try {
            const r = await axios.post('/api/mitre/generate');
            setGenResult(r.data);
        } catch (e: any) {
            setGenResult({ message: `Error: ${e.message}` });
        } finally {
            setGenerating(false);
        }
    };

    const handleExportPdf = async () => {
        setGenerating(true);
        try {
            const r = await axios.post('/api/mitre/export-pdf', {}, { responseType: 'blob' });
            if (!r.data) throw new Error('Server returned empty response');
            const url = window.URL.createObjectURL(new Blob([r.data]));
            const a = document.createElement('a');
            a.href = url;
            a.download = `MITRE_ATTACK_Coverage_Assessment_${new Date().toISOString().slice(0, 10)}.pdf`;
            a.click();
        } catch (e: any) {
            alert(`Failed to export PDF: ${e.message}`);
        } finally {
            setGenerating(false);
        }
    };

    const handleExportHtml = async () => {
        setGenerating(true);
        try {
            const r = await axios.post('/api/mitre/export-html', {}, { responseType: 'blob' });
            if (!r.data) throw new Error('Server returned empty response');
            const url = window.URL.createObjectURL(new Blob([r.data]));
            const a = document.createElement('a');
            a.href = url;
            a.download = `MITRE_ATTACK_Coverage_Report_${new Date().toISOString().slice(0, 10)}.html`;
            a.click();
        } catch (e: any) {
            alert(`Failed to export HTML: ${e.message}`);
        } finally {
            setGenerating(false);
        }
    };

    if (loading) return (
        <div style={{ padding: 40, textAlign: 'center' }}>
            <div className="spinner spinner-lg" style={{ margin: '0 auto 12px' }} />
            <div className="text-muted">Loading MITRE ATT&CK data…</div>
        </div>
    );

    const summary = data.summary;
    const tactics = data.tactics || [];
    const rules = data.recommended_rules || [];
    const logSources = data.missing_log_sources || [];

    const missingCount = logSources.filter(s => s.status === 'ABSENT').length;
    const partialCount = logSources.filter(s => s.status === 'PARTIAL').length;

    const TABS: Array<{ id: TabId; label: string; icon: any; badge?: string; badgeClass?: string }> = [
        { id: 'heatmap',             label: 'Heatmap',            icon: faFire },
        { id: 'tactics',             label: 'Tactic Detail',      icon: faClipboardList },
        { id: 'use-cases',           label: 'Use Cases',          icon: faListCheck,
          badge: useCases ? String(useCases.summary.total) : undefined },
        { id: 'false-positives',     label: 'False Positives',    icon: faTriangleExclamation,
          badge: fpData ? `${fpData.summary.fp_rate}%` : undefined },
        { id: 'technique-activity',  label: 'Technique Activity', icon: faBullseye },
        { id: 'rules',               label: 'Recommended Rules',  icon: faThumbtack,
          badge: rules.length ? String(rules.length) : undefined },
        { id: 'log-sources',         label: 'Log Sources',        icon: faDatabase,
          badge: logSources.length ? `${missingCount} absent` : undefined,
          badgeClass: missingCount > 0 ? 'badge-critical' : 'badge-muted' },
    ];

    // ── Classification palette ───────────────────────────────────────────────
    const CLASS_COLOR: Record<string, string> = {
        TruePositive:   'var(--low)',
        FalsePositive:  'var(--critical)',
        BenignPositive: 'var(--high)',
        Undetermined:   'var(--medium)',
        Unclassified:   'var(--text-muted)',
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

            {/* ── Header ── */}
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faShieldHalved} style={{ marginRight: 12, fontSize: '0.9em', color: 'var(--pwc-orange)' }} />
                            MITRE ATT&amp;CK Coverage
                        </div>
                        <div className="page-subtitle">Detection coverage · use cases · false positive analysis across {tactics.length} MITRE tactics</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                        <button className="btn btn-secondary" onClick={handleExportHtml} disabled={generating}>
                            <FontAwesomeIcon icon={faFileCode} style={{ marginRight: 8 }} />Export HTML
                        </button>
                        <button className="btn btn-secondary" onClick={handleExportPdf} disabled={generating}>
                            <FontAwesomeIcon icon={faFilePdf} style={{ marginRight: 8 }} />Export PDF
                        </button>
                        <button className="btn btn-primary" onClick={handleGenerate} disabled={generating}>
                            {generating
                                ? <span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />
                                : <FontAwesomeIcon icon={faFileLines} style={{ marginRight: 8 }} />}
                            {generating ? ' Generating…' : ' Refresh Metrics'}
                        </button>
                    </div>
                </div>
                {genResult && (
                    <div style={{
                        marginTop: 10, padding: '10px 14px',
                        background: 'var(--risk-low-bg)', border: '1px solid rgba(63,185,80,0.3)',
                        borderRadius: 'var(--radius-sm)', fontSize: 12, color: 'var(--low)',
                        display: 'flex', alignItems: 'center', gap: 8,
                    }}>
                        <FontAwesomeIcon icon={faCircleCheck} />
                        {genResult.message}
                        {genResult.generated?.map(f => (
                            <span key={f.name} style={{ marginLeft: 8, fontFamily: 'monospace', color: 'var(--text-primary)' }}>{f.name}</span>
                        ))}
                    </div>
                )}
            </div>

            {/* ── KPI Row ── */}
            {summary && (
                <div style={{ padding: '16px 28px', borderBottom: '1px solid var(--border)', background: 'var(--bg-base)', flexShrink: 0 }}>
                    <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(8, 1fr)' }}>
                        {[
                            { label: 'Overall Coverage', value: `${summary.overall_coverage}%`, color: coverageColor(summary.overall_coverage) },
                            { label: 'Risk Level', value: summary.assessment, color: summary.assessment === 'CRITICAL' ? 'var(--critical)' : summary.assessment === 'HIGH' ? 'var(--high)' : 'var(--medium)' },
                            { label: 'Tactics Covered', value: `${summary.tactics_with_coverage}/${summary.total_tactics}` },
                            { label: 'Techniques', value: `${summary.covered_techniques}/${summary.total_techniques}` },
                            { label: 'Total Incidents', value: summary.total_incidents.toLocaleString() },
                            { label: 'Recommended Rules', value: String(rules.length), color: 'var(--high)' },
                            { label: 'Absent Log Sources', value: String(missingCount), color: missingCount > 0 ? 'var(--critical)' : 'var(--low)' },
                            { label: 'Partial Log Sources', value: String(partialCount), color: partialCount > 0 ? 'var(--high)' : 'var(--low)' },
                        ].map(k => (
                            <div key={k.label} className="stat-tile" style={{ padding: 12 }}>
                                <div className="stat-tile-value" style={{ fontSize: 22, color: k.color }}>{k.value}</div>
                                <div className="stat-tile-label" style={{ fontSize: 10 }}>{k.label}</div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* ── Tabs ── */}
            <div style={{ padding: '0 28px', background: 'var(--bg-base)', borderBottom: '1px solid var(--border)', flexShrink: 0, overflowX: 'auto' }}>
                <div className="tabs" style={{ margin: 0, whiteSpace: 'nowrap' }}>
                    {TABS.map(t => (
                        <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                            <FontAwesomeIcon icon={t.icon} style={{ marginRight: 7 }} />
                            {t.label}
                            {t.badge !== undefined && (
                                <span className={`badge ${t.badgeClass ?? 'badge-muted'}`} style={{ marginLeft: 7, fontSize: 10, padding: '1px 6px' }}>{t.badge}</span>
                            )}
                        </button>
                    ))}
                </div>
            </div>

            {/* ── Content ── */}
            <div style={{ flex: 1, overflow: 'auto', padding: '20px 28px' }}>

                {/* ── Heatmap ── */}
                {tab === 'heatmap' && (
                    <div>
                        {/* Radial gauge + summary */}
                        {summary && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: 32, marginBottom: 24 }}>
                                <div style={{ position: 'relative', width: 160, height: 160, flexShrink: 0 }}>
                                    <ResponsiveContainer width="100%" height="100%">
                                        <RadialBarChart
                                            cx="50%" cy="50%"
                                            innerRadius="60%" outerRadius="90%"
                                            data={[{ value: summary.overall_coverage || 0, fill: '#D04A02' }]}
                                            startAngle={90} endAngle={-270}
                                        >
                                            <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
                                            <RadialBar dataKey="value" cornerRadius={6} background={{ fill: '#F0F0F0' }} />
                                        </RadialBarChart>
                                    </ResponsiveContainer>
                                    <div style={{
                                        position: 'absolute', inset: 0,
                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        flexDirection: 'column', pointerEvents: 'none',
                                    }}>
                                        <div className="card-metric-value" style={{ fontSize: 26, color: 'var(--pwc-orange)' }}>
                                            {summary.overall_coverage || 0}%
                                        </div>
                                        <div className="card-metric-label">Coverage</div>
                                    </div>
                                </div>
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                                        MITRE ATT&amp;CK Coverage
                                    </div>
                                    <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>
                                        {summary.covered_techniques} / {summary.total_techniques} techniques covered
                                    </div>
                                    <span className={`badge ${riskBadge(summary.overall_coverage)}`} style={{ fontSize: 12, padding: '4px 12px' }}>
                                        Assessment: {summary.assessment}
                                    </span>
                                </div>
                            </div>
                        )}
                        <div style={{ marginBottom: 16, fontSize: 12, color: 'var(--text-muted)' }}>
                            Click a tactic cell to drill into technique details. Red = no coverage, green = strong coverage.
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 20 }}>
                            {tactics.map(t => (
                                <div
                                    key={t.id}
                                    onClick={() => { setSelectedTactic(t.id); setTab('tactics'); }}
                                    className="card-elevated"
                                    style={{
                                        background: (t.coverage || 0) < 30 ? 'rgba(192,57,43,0.08)'
                                                 : (t.coverage || 0) < 60  ? 'rgba(230,126,34,0.08)'
                                                 : 'rgba(39,174,96,0.08)',
                                        border: `1px solid ${(t.coverage || 0) < 30 ? 'rgba(192,57,43,0.2)'
                                                             : (t.coverage || 0) < 60 ? 'rgba(230,126,34,0.2)'
                                                             : 'rgba(39,174,96,0.2)'}`,
                                        padding: '16px',
                                        cursor: 'pointer',
                                    }}
                                >
                                    <div style={{ fontSize: 24, fontWeight: 800, marginBottom: 4,
                                                  color: (t.coverage || 0) < 30 ? 'var(--critical)'
                                                       : (t.coverage || 0) < 60 ? 'var(--high)' : 'var(--low)' }}>
                                        {t.coverage || 0}%
                                    </div>
                                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 4 }}>
                                        {t.name}
                                    </div>
                                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 8 }}>
                                        {t.techniques_covered}/{t.techniques_total} techniques · {t.incidents.toLocaleString()} incidents
                                    </div>
                                    <div className="progress-bar-wrap" style={{ height: 5 }}>
                                        <div className={`progress-bar-fill ${(t.coverage || 0) < 30 ? 'red' : (t.coverage || 0) < 60 ? 'yellow' : 'green'}`}
                                             style={{ width: `${t.coverage || 0}%` }} />
                                    </div>
                                </div>
                            ))}
                        </div>
                        <div className="card" style={{ display: 'flex', gap: 20, alignItems: 'center', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Legend:</span>
                            {[
                                { label: 'No Coverage (0%)', color: '#C0392B' },
                                { label: 'Critical (<30%)',  color: '#E74C3C' },
                                { label: 'Weak (30–50%)',    color: '#E67E22' },
                                { label: 'Fair (50–70%)',    color: '#D4AC0D' },
                                { label: 'Good (70–85%)',    color: '#27AE60' },
                                { label: 'Excellent (85%+)', color: '#1E8449' },
                            ].map(l => (
                                <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                    <div style={{ width: 12, height: 12, borderRadius: 3, background: l.color, flexShrink: 0 }} />
                                    {l.label}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* ── Tactic Detail ── */}
                {tab === 'tactics' && (
                    <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: 16 }}>
                        <div className="card" style={{ padding: 0, overflow: 'hidden', alignSelf: 'start' }}>
                            {tactics.map(t => (
                                <button
                                    key={t.id}
                                    onClick={() => setSelectedTactic(t.id)}
                                    style={{
                                        width: '100%', textAlign: 'left', padding: '10px 14px',
                                        background: selectedTactic === t.id ? 'var(--pwc-orange-light)' : 'transparent',
                                        border: 'none', borderLeft: `3px solid ${selectedTactic === t.id ? 'var(--pwc-orange)' : 'transparent'}`,
                                        cursor: 'pointer', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8,
                                    }}
                                >
                                    <div style={{ flex: 1 }}>
                                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{t.name}</div>
                                        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{t.coverage}% · {t.incidents} incidents</div>
                                    </div>
                                    <div style={{ width: 34, height: 34, borderRadius: '50%', background: coverageBg(t.coverage), border: `1px solid ${coverageColor(t.coverage)}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: coverageColor(t.coverage), flexShrink: 0 }}>
                                        {t.coverage}%
                                    </div>
                                </button>
                            ))}
                        </div>
                        {selected ? (
                            <div className="card" style={{ alignSelf: 'start' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                                    <div>
                                        <div style={{ fontSize: 18, fontWeight: 700 }}>{selected.name}</div>
                                        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
                                            {selected.id} · {selected.techniques_covered}/{selected.techniques_total} techniques covered
                                        </div>
                                    </div>
                                    <span className={`badge ${riskBadge(selected.coverage)}`} style={{ fontSize: 13 }}>{selected.coverage}% Coverage</span>
                                </div>
                                <ProgressBar pct={selected.coverage} height={8} />
                                <div className="data-table-wrap" style={{ marginTop: 16 }}>
                                    <table className="data-table">
                                        <thead>
                                            <tr>
                                                <th>Technique ID</th>
                                                <th>Name</th>
                                                <th style={{ width: 110 }}>Status</th>
                                                <th style={{ width: 160 }}>Coverage Score</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {selected.techniques_list.map((tech, i) => (
                                                <tr key={i}>
                                                    <td><code className="mono" style={{ fontSize: 11 }}>{tech.id}</code></td>
                                                    <td style={{ fontSize: 12 }}>{tech.name}</td>
                                                    <td>
                                                        <span className={`badge ${tech.covered ? 'badge-low' : 'badge-critical'}`} style={{ display: 'flex', alignItems: 'center', gap: 6, width: 'fit-content' }}>
                                                            <FontAwesomeIcon icon={tech.covered ? faCheck : faXmark} style={{ fontSize: 10 }} />
                                                            {tech.covered ? 'Covered' : 'Gap'}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                            <ProgressBar pct={tech.score} height={4} />
                                                            <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>{tech.score}%</span>
                                                        </div>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        ) : (
                            <div className="card">
                                <div className="empty-state">
                                    <div className="empty-state-icon"><FontAwesomeIcon icon={faArrowLeft} style={{ opacity: 0.3 }} /></div>
                                    <div className="empty-state-text">Select a tactic to see technique details</div>
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* ── Use Cases ── */}
                {tab === 'use-cases' && (
                    ucLoading ? <LoadingPane /> : (
                        <div>
                            {/* Summary tiles */}
                            {useCases && (
                                <>
                                    <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 16 }}>
                                        {[
                                            { label: 'Total Rules',   value: useCases.summary.total,   color: 'var(--text-primary)' },
                                            { label: 'Enabled',       value: useCases.summary.enabled,  color: 'var(--low)' },
                                            { label: 'Disabled',      value: useCases.summary.disabled, color: 'var(--critical)' },
                                            { label: 'Showing',       value: filteredUC.length,          color: 'var(--pwc-orange)' },
                                        ].map(k => (
                                            <div key={k.label} className="stat-tile">
                                                <div className="stat-tile-value" style={{ color: k.color }}>{k.value}</div>
                                                <div className="stat-tile-label">{k.label}</div>
                                            </div>
                                        ))}
                                    </div>
                                    {/* Kind breakdown pills */}
                                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
                                        {Object.entries(useCases.summary.by_kind).map(([kind, count]) => (
                                            <div key={kind} style={{ display: 'flex', alignItems: 'center', gap: 5, background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 20, padding: '3px 10px', fontSize: 11 }}>
                                                <span style={{ fontWeight: 600 }}>{kind}</span>
                                                <span className="badge badge-muted" style={{ fontSize: 10, padding: '1px 5px' }}>{count}</span>
                                            </div>
                                        ))}
                                    </div>
                                </>
                            )}

                            {/* Filters */}
                            <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
                                <div style={{ position: 'relative', flex: '1 1 220px', minWidth: 180 }}>
                                    <FontAwesomeIcon icon={faMagnifyingGlass} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 12 }} />
                                    <input
                                        className="form-input"
                                        placeholder="Search rule name or technique…"
                                        value={ucSearch}
                                        onChange={e => setUcSearch(e.target.value)}
                                        style={{ paddingLeft: 30, height: 34 }}
                                    />
                                </div>
                                {/* Enabled / Disabled filter */}
                                <div style={{ display: 'flex', gap: 6 }}>
                                    {(['All', 'Enabled', 'Disabled'] as const).map(s => (
                                        <button
                                            key={s}
                                            onClick={() => setUcStatusFilter(s)}
                                            className={`badge ${ucStatusFilter === s ? (s === 'Enabled' ? 'badge-low' : s === 'Disabled' ? 'badge-critical' : 'badge-pwc') : 'badge-muted'}`}
                                            style={{ cursor: 'pointer', border: 'none', padding: '4px 10px', fontSize: 11 }}
                                        >{s}</button>
                                    ))}
                                </div>
                                <select
                                    className="form-select"
                                    value={ucKindFilter}
                                    onChange={e => setUcKindFilter(e.target.value)}
                                    style={{ height: 34, fontSize: 12 }}
                                >
                                    <option value="All">All Kinds</option>
                                    {ucKinds.map(k => <option key={k} value={k}>{k}</option>)}
                                </select>
                                <select
                                    className="form-select"
                                    value={ucTacticFilter}
                                    onChange={e => setUcTacticFilter(e.target.value)}
                                    style={{ height: 34, fontSize: 12 }}
                                >
                                    <option value="All">All Tactics</option>
                                    {ucTactics.map(t => <option key={t} value={t}>{t}</option>)}
                                </select>
                            </div>

                            {/* Tactic groups */}
                            {ucTactics
                                .filter(tactic => ucTacticFilter === 'All' || tactic === ucTacticFilter)
                                .map(tactic => {
                                    const group = useCases?.by_tactic[tactic];
                                    const rows = filteredUC.filter(uc =>
                                        uc.tactics.includes(tactic) ||
                                        (tactic === 'No Tactic Mapped' && uc.tactics.length === 0)
                                    );
                                    if (!rows.length) return null;
                                    return (
                                        <div key={tactic} style={{ marginBottom: 20 }}>
                                            {/* Tactic header */}
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, padding: '6px 0', borderBottom: '2px solid var(--pwc-orange)' }}>
                                                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>{tactic}</div>
                                                {group && <>
                                                    <span className="badge badge-muted"  style={{ fontSize: 10 }}>{group.total} rules</span>
                                                    <span className="badge badge-low"     style={{ fontSize: 10 }}>{group.enabled} enabled</span>
                                                    {group.disabled > 0 && <span className="badge badge-critical" style={{ fontSize: 10 }}>{group.disabled} disabled</span>}
                                                </>}
                                            </div>
                                            <div className="data-table-wrap">
                                                <table className="data-table">
                                                    <thead>
                                                        <tr>
                                                            <th>Rule Name</th>
                                                            <th style={{ width: 90 }}>Kind</th>
                                                            <th style={{ width: 80 }}>Severity</th>
                                                            <th>Techniques</th>
                                                            <th style={{ width: 90 }}>Status</th>
                                                            <th style={{ width: 90 }}>Frequency</th>
                                                            <th style={{ width: 110 }}>Last Modified</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {rows.map((uc, i) => (
                                                            <tr key={i} style={{ opacity: uc.enabled ? 1 : 0.6 }}>
                                                                <td>
                                                                    <div style={{ fontSize: 12, fontWeight: 500 }}>{uc.name}</div>
                                                                    {uc.description && <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 320 }}>{uc.description}</div>}
                                                                </td>
                                                                <td>
                                                                    <span className="badge badge-muted" style={{ fontSize: 10 }}>{uc.kind}</span>
                                                                </td>
                                                                <td>
                                                                    {uc.severity
                                                                        ? <span className={`badge ${severityBadge(uc.severity)}`} style={{ fontSize: 10 }}>{uc.severity}</span>
                                                                        : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>}
                                                                </td>
                                                                <td>
                                                                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                                                                        {uc.techniques.slice(0, 4).map(t => (
                                                                            <code key={t} className="mono" style={{ fontSize: 10, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 3, padding: '1px 5px' }}>{t}</code>
                                                                        ))}
                                                                        {uc.techniques.length > 4 && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{uc.techniques.length - 4}</span>}
                                                                        {uc.techniques.length === 0 && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>—</span>}
                                                                    </div>
                                                                </td>
                                                                <td>
                                                                    <span className={`badge ${uc.enabled ? 'badge-low' : 'badge-critical'}`} style={{ fontSize: 10 }}>
                                                                        <FontAwesomeIcon icon={uc.enabled ? faCheck : faXmark} style={{ marginRight: 5, fontSize: 9 }} />
                                                                        {uc.enabled ? 'Enabled' : 'Disabled'}
                                                                    </span>
                                                                </td>
                                                                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{uc.query_frequency || '—'}</td>
                                                                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{relativeTime(uc.last_modified)}</td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
                                    );
                                })
                            }
                            {filteredUC.length === 0 && !ucLoading && (
                                <div className="empty-state">
                                    <div className="empty-state-icon"><FontAwesomeIcon icon={faListCheck} style={{ opacity: 0.3 }} /></div>
                                    <div className="empty-state-text">No use cases match the current filters</div>
                                </div>
                            )}
                        </div>
                    )
                )}

                {/* ── False Positives ── */}
                {tab === 'false-positives' && (
                    fpLoading ? <LoadingPane /> : fpData ? (
                        <div>
                            {/* KPI tiles */}
                            <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: 20 }}>
                                {[
                                    { label: 'FP Rate',          value: `${fpData.summary.fp_rate}%`,         color: fpData.summary.fp_rate > 30 ? 'var(--critical)' : fpData.summary.fp_rate > 15 ? 'var(--high)' : 'var(--low)' },
                                    { label: 'True Positive',    value: fpData.summary.true_positive,         color: 'var(--low)' },
                                    { label: 'False Positive',   value: fpData.summary.false_positive,        color: 'var(--critical)' },
                                    { label: 'Benign Positive',  value: fpData.summary.benign_positive,       color: 'var(--high)' },
                                    { label: 'Undetermined',     value: fpData.summary.undetermined,          color: 'var(--medium)' },
                                ].map(k => (
                                    <div key={k.label} className="stat-tile">
                                        <div className="stat-tile-value" style={{ color: k.color }}>{typeof k.value === 'number' ? k.value.toLocaleString() : k.value}</div>
                                        <div className="stat-tile-label">{k.label}</div>
                                    </div>
                                ))}
                            </div>

                            {/* Classification bar */}
                            {fpData.summary.total > 0 && (
                                <div className="card" style={{ marginBottom: 20 }}>
                                    <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12 }}>Incident Classification Breakdown</div>
                                    <div style={{ display: 'flex', height: 20, borderRadius: 4, overflow: 'hidden', marginBottom: 10 }}>
                                        {(
                                            [
                                                ['TruePositive',   fpData.summary.true_positive],
                                                ['FalsePositive',  fpData.summary.false_positive],
                                                ['BenignPositive', fpData.summary.benign_positive],
                                                ['Undetermined',   fpData.summary.undetermined],
                                                ['Unclassified',   fpData.summary.unclassified],
                                            ] as [string, number][]
                                        ).filter(([, v]) => v > 0).map(([cls, val]) => (
                                            <div
                                                key={cls}
                                                title={`${cls}: ${val}`}
                                                style={{
                                                    flex: val,
                                                    background: CLASS_COLOR[cls] || 'var(--text-muted)',
                                                    transition: 'flex 0.4s',
                                                }}
                                            />
                                        ))}
                                    </div>
                                    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                                        {(
                                            [
                                                ['TruePositive',   fpData.summary.true_positive],
                                                ['FalsePositive',  fpData.summary.false_positive],
                                                ['BenignPositive', fpData.summary.benign_positive],
                                                ['Undetermined',   fpData.summary.undetermined],
                                                ['Unclassified',   fpData.summary.unclassified],
                                            ] as [string, number][]
                                        ).filter(([, v]) => v > 0).map(([cls, val]) => (
                                            <div key={cls} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
                                                <div style={{ width: 10, height: 10, borderRadius: 2, background: CLASS_COLOR[cls], flexShrink: 0 }} />
                                                <span style={{ color: 'var(--text-secondary)' }}>{cls}</span>
                                                <span style={{ fontWeight: 700 }}>{val.toLocaleString()}</span>
                                                <span style={{ color: 'var(--text-muted)' }}>({((val / fpData.summary.total) * 100).toFixed(1)}%)</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
                                {/* Top FP rules */}
                                <div className="card">
                                    <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: 'var(--critical)', fontSize: 12 }} />
                                        Top FP-Generating Rules
                                    </div>
                                    {fpData.top_fp_rules.length === 0 ? (
                                        <div style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', padding: 20 }}>No FP data in selected period</div>
                                    ) : (
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                            {fpData.top_fp_rules.map((r, i) => {
                                                const maxFp = Math.max(...fpData.top_fp_rules.map(x => x.fp_count), 1);
                                                return (
                                                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                                        <div style={{ width: 18, fontSize: 10, color: 'var(--text-muted)', textAlign: 'right', flexShrink: 0 }}>{i + 1}</div>
                                                        <div style={{ flex: 1, minWidth: 0 }}>
                                                            <div style={{ fontSize: 11, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={r.title}>{r.title}</div>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 3 }}>
                                                                <div className="progress-bar-wrap" style={{ flex: 1, height: 4 }}>
                                                                    <div className="progress-bar-fill red" style={{ width: `${(r.fp_count / maxFp) * 100}%` }} />
                                                                </div>
                                                                <span style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 }}>{r.fp_count} FPs</span>
                                                            </div>
                                                        </div>
                                                        <span className={`badge ${severityBadge(r.severity)}`} style={{ fontSize: 9, flexShrink: 0 }}>{r.severity}</span>
                                                        {r.avg_mttr_hours > 0 && (
                                                            <span style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 }}>{formatHours(r.avg_mttr_hours)}</span>
                                                        )}
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    )}
                                </div>

                                {/* Tuning suggestion panel */}
                                <div className="card">
                                    <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <FontAwesomeIcon icon={faComment} style={{ color: 'var(--pwc-orange)', fontSize: 12 }} />
                                        Fine-Tuning Suggestions
                                    </div>
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
                                        Analyst comments from false-positive &amp; benign-positive incidents
                                    </div>
                                    {fpData.fine_tuning_comments.length === 0 ? (
                                        <div style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', padding: 20 }}>
                                            No comments found on FP incidents
                                        </div>
                                    ) : (
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 340, overflowY: 'auto' }}>
                                            {fpData.fine_tuning_comments.map((c, i) => (
                                                <div key={i} style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px' }}>
                                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                                                        <div style={{ fontSize: 11, fontWeight: 600, flex: 1, marginRight: 8, color: 'var(--text-primary)' }}>{c.title}</div>
                                                        <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                                                            <span className={`badge ${severityBadge(c.severity)}`} style={{ fontSize: 9 }}>{c.severity}</span>
                                                            <span className="badge badge-muted" style={{ fontSize: 9 }}>{c.classification}</span>
                                                        </div>
                                                    </div>
                                                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5, fontStyle: 'italic' }}>
                                                        "{c.comment}"
                                                    </div>
                                                    {c.comment_time && (
                                                        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 6 }}>{relativeTime(c.comment_time)}</div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="empty-state">
                            <div className="empty-state-text">Could not load false positive data</div>
                        </div>
                    )
                )}

                {/* ── Technique Activity ── */}
                {tab === 'technique-activity' && (
                    techLoading ? <LoadingPane /> : (
                        <div>
                            {techHits.length === 0 ? (
                                <div className="empty-state">
                                    <div className="empty-state-icon"><FontAwesomeIcon icon={faBullseye} style={{ opacity: 0.3 }} /></div>
                                    <div className="empty-state-text">No technique activity data in the last 30 days</div>
                                </div>
                            ) : (
                                <>
                                    {/* Horizontal bar chart */}
                                    <div className="card" style={{ marginBottom: 20 }}>
                                        <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 16 }}>Top MITRE Techniques by Alert Volume (Last 30 Days)</div>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                            {techHits.slice(0, 15).map(t => (
                                                <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                                    <code className="mono" style={{ fontSize: 11, width: 70, flexShrink: 0, color: 'var(--pwc-orange)' }}>{t.id}</code>
                                                    <div style={{ flex: 1, background: '#E5E5E5', borderRadius: 3, height: 18, overflow: 'hidden', position: 'relative' }}>
                                                        {/* Stacked: high / medium / low */}
                                                        <div style={{ display: 'flex', height: '100%' }}>
                                                            <div style={{ width: `${(t.high_count / maxTechCount) * 100}%`, background: 'var(--critical)', transition: 'width 0.6s' }} />
                                                            <div style={{ width: `${(t.medium_count / maxTechCount) * 100}%`, background: 'var(--high)', transition: 'width 0.6s' }} />
                                                            <div style={{ width: `${(t.low_count / maxTechCount) * 100}%`, background: 'var(--medium)', transition: 'width 0.6s' }} />
                                                        </div>
                                                    </div>
                                                    <span style={{ fontSize: 12, fontWeight: 700, width: 55, textAlign: 'right', flexShrink: 0 }}>
                                                        {t.alert_count.toLocaleString()}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                        <div style={{ display: 'flex', gap: 16, marginTop: 12, fontSize: 11, color: 'var(--text-muted)' }}>
                                            {[['var(--critical)', 'High'], ['var(--high)', 'Medium'], ['var(--medium)', 'Low']].map(([c, l]) => (
                                                <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                                                    <div style={{ width: 10, height: 10, borderRadius: 2, background: c, flexShrink: 0 }} />{l}
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    {/* Full table */}
                                    <div className="card" style={{ padding: 0 }}>
                                        <div className="data-table-wrap">
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th>Technique ID</th>
                                                        <th>Tactic(s)</th>
                                                        <th style={{ width: 90 }}>Total Alerts</th>
                                                        <th style={{ width: 70 }}>High</th>
                                                        <th style={{ width: 70 }}>Medium</th>
                                                        <th style={{ width: 70 }}>Low</th>
                                                        <th style={{ width: 80 }}>Rules</th>
                                                        <th style={{ width: 100 }}>Last Seen</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {techHits.map((t, i) => (
                                                        <tr key={i}>
                                                            <td><code className="mono" style={{ fontSize: 11, color: 'var(--pwc-orange)' }}>{t.id}</code></td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{t.tactics || '—'}</td>
                                                            <td style={{ fontWeight: 700 }}>{t.alert_count.toLocaleString()}</td>
                                                            <td><span className="badge badge-critical" style={{ fontSize: 10 }}>{t.high_count || '—'}</span></td>
                                                            <td><span className="badge badge-high" style={{ fontSize: 10 }}>{t.medium_count || '—'}</span></td>
                                                            <td><span className="badge badge-medium" style={{ fontSize: 10 }}>{t.low_count || '—'}</span></td>
                                                            <td style={{ fontSize: 11 }}>{t.unique_rules}</td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{relativeTime(t.last_seen)}</td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </>
                            )}
                        </div>
                    )
                )}

                {/* ── Recommended Rules ── */}
                {tab === 'rules' && (
                    <div>
                        <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
                            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                {rules.length} detection rules covering all MITRE tactics — sorted by priority. Deploy in order.
                            </div>
                            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                                {(['CRITICAL', 'HIGH', 'MEDIUM'] as const).map(p => {
                                    const cnt = rules.filter(r => r.priority === p).length;
                                    return (
                                        <span key={p} className={`badge ${priorityBadge(p)}`} style={{ fontSize: 10 }}>
                                            {p}: {cnt}
                                        </span>
                                    );
                                })}
                            </div>
                        </div>
                        {rules.map(rule => (
                            <div key={rule.id} className="card" style={{ marginBottom: 12 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                                            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)' }}>#{rule.id}</span>
                                            <span className={`badge ${priorityBadge(rule.priority)}`}>{rule.priority}</span>
                                            <code className="mono" style={{ fontSize: 11, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 3, padding: '1px 6px', color: 'var(--pwc-orange)' }}>{rule.technique}</code>
                                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{rule.tactic_name}</span>
                                        </div>
                                        <div style={{ fontSize: 14, fontWeight: 700 }}>{rule.technique_name}</div>
                                    </div>
                                    <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: 16 }}>
                                        <div className="card-metric-value" style={{ fontSize: 18, color: 'var(--pwc-orange)' }}>~{rule.estimated_incidents.toLocaleString()}</div>
                                        <div className="card-metric-label">est. incidents/qtr</div>
                                        <div style={{ marginTop: 4 }}>
                                            <span className={`badge ${rule.implementation_effort === 'Low' ? 'badge-low' : rule.implementation_effort === 'High' ? 'badge-critical' : 'badge-high'}`} style={{ fontSize: 10 }}>
                                                {rule.implementation_effort} effort
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 10, lineHeight: 1.6 }}>
                                    {rule.description}
                                </div>
                                {(rule.detection_method || rule.mitre_data_source) && (
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
                                        {rule.mitre_data_source && (
                                            <div style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 4, padding: '8px 10px' }}>
                                                <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 3 }}>Data Source</div>
                                                <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{rule.mitre_data_source}</div>
                                            </div>
                                        )}
                                        {rule.detection_method && (
                                            <div style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 4, padding: '8px 10px' }}>
                                                <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 3 }}>Detection Method</div>
                                                <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{rule.detection_method}</div>
                                            </div>
                                        )}
                                    </div>
                                )}
                                <div style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 4, padding: '10px 12px' }}>
                                    <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 6 }}>KQL Detection Template</div>
                                    <pre className="mono" style={{ margin: 0, fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--pwc-orange)', lineHeight: 1.6 }}>{rule.rule_template}</pre>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* ── Log Sources ── */}
                {tab === 'log-sources' && (
                    <div>
                        {/* Missing log sources chips */}
                        {logSources && logSources.filter(s => s.status === 'ABSENT').length > 0 && (
                            <div className="card" style={{ marginBottom: 20 }}>
                                <div className="card-title">Missing Log Sources</div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                    {logSources.filter(s => s.status === 'ABSENT').map((src, i) => (
                                        <span key={i}
                                            className="chip"
                                            style={{ borderColor: 'rgba(192,57,43,0.4)', color: 'var(--critical)',
                                                     background: 'rgba(192,57,43,0.06)', cursor: 'pointer' }}
                                            onClick={() => navigator.clipboard?.writeText(src.source_name)}
                                            title="Click to copy"
                                        >
                                            {src.source_name}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                        {/* Summary strip */}
                        <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 20 }}>
                            {[
                                { label: 'Total Assessed',    value: logSources.length,   color: 'var(--text-primary)' },
                                { label: 'Absent',            value: missingCount,         color: 'var(--critical)' },
                                { label: 'Partial',           value: partialCount,         color: 'var(--high)' },
                                { label: 'Est. Coverage Gain', value: `+${logSources.reduce((s, l) => s + l.estimated_coverage_gain, 0)}%`, color: 'var(--low)' },
                            ].map(k => (
                                <div key={k.label} className="stat-tile">
                                    <div className="stat-tile-value" style={{ color: k.color }}>{k.value}</div>
                                    <div className="stat-tile-label">{k.label}</div>
                                </div>
                            ))}
                        </div>

                        <div style={{ marginBottom: 12, fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                            The following log sources are absent or only partially connected to this Sentinel workspace. Connecting them would improve MITRE ATT&amp;CK coverage as indicated. Sources are ordered by priority.
                        </div>

                        {/* Group by status */}
                        {(['ABSENT', 'PARTIAL'] as const).map(status => {
                            const group = logSources.filter(s => s.status === status);
                            if (!group.length) return null;
                            const statusColor = status === 'ABSENT' ? 'var(--critical)' : 'var(--high)';
                            const statusLabel = status === 'ABSENT' ? 'Absent — Not Connected' : 'Partial — Incomplete Coverage';
                            return (
                                <div key={status} style={{ marginBottom: 28 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, paddingBottom: 8, borderBottom: `2px solid ${statusColor}` }}>
                                        <FontAwesomeIcon icon={status === 'ABSENT' ? faXmark : faExclamationCircle} style={{ color: statusColor, fontSize: 13 }} />
                                        <span style={{ fontSize: 13, fontWeight: 700, color: statusColor }}>{statusLabel}</span>
                                        <span className="badge badge-muted" style={{ fontSize: 10 }}>{group.length} source{group.length !== 1 ? 's' : ''}</span>
                                    </div>
                                    {group.map(src => (
                                        <div key={src.id} className="card" style={{ marginBottom: 12, borderLeft: `3px solid ${statusColor}` }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                                                <div style={{ flex: 1, minWidth: 0 }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                                                        <FontAwesomeIcon icon={faDatabase} style={{ color: statusColor, fontSize: 12 }} />
                                                        <span style={{ fontSize: 14, fontWeight: 700 }}>{src.source_name}</span>
                                                        <span className="badge badge-muted" style={{ fontSize: 10 }}>{src.category}</span>
                                                        <span className={`badge ${src.priority === 'CRITICAL' ? 'badge-critical' : src.priority === 'HIGH' ? 'badge-high' : 'badge-medium'}`} style={{ fontSize: 10 }}>{src.priority}</span>
                                                    </div>
                                                    <code className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 3, padding: '3px 8px', display: 'inline-block', marginBottom: 8 }}>
                                                        {src.sentinel_table}
                                                    </code>
                                                </div>
                                                <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: 16 }}>
                                                    <div className="card-metric-value" style={{ fontSize: 22, color: 'var(--low)' }}>+{src.estimated_coverage_gain}%</div>
                                                    <div className="card-metric-label">coverage gain</div>
                                                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginTop: 4 }}>{src.technique_count} techniques</div>
                                                </div>
                                            </div>

                                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12, lineHeight: 1.6 }}>
                                                {src.description}
                                            </div>

                                            {/* Tactics + techniques pills */}
                                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
                                                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                                                    <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Tactics:</span>
                                                    {src.tactics_affected.map(t => (
                                                        <span key={t} className="badge badge-muted" style={{ fontSize: 10 }}>{t}</span>
                                                    ))}
                                                </div>
                                            </div>
                                            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 12, alignItems: 'center' }}>
                                                <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Techniques:</span>
                                                {src.techniques_covered.map(t => (
                                                    <code key={t} className="mono" style={{ fontSize: 10, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 3, padding: '1px 6px', color: 'var(--pwc-orange)' }}>{t}</code>
                                                ))}
                                            </div>

                                            {/* Implementation guidance */}
                                            <div style={{ background: 'rgba(39,174,96,0.06)', border: '1px solid rgba(39,174,96,0.2)', borderRadius: 4, padding: '10px 12px' }}>
                                                <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: 'var(--low)', marginBottom: 4 }}>Implementation Guidance</div>
                                                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{src.implementation}</div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            );
                        })}

                        {logSources.length === 0 && (
                            <div className="empty-state">
                                <div className="empty-state-icon"><FontAwesomeIcon icon={faDatabase} style={{ opacity: 0.3 }} /></div>
                                <div className="empty-state-text">No log source assessment data available</div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
