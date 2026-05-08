import { useState, useEffect, useMemo } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faChartBar, faClock, faUsers, faShieldHalved,
    faArrowTrendDown, faFilePdf, faFileCode, faRefresh,
    faList, faRobot, faSearch, faFilter, faRepeat,
    faWandMagicSparkles, faCircleCheck, faCircleXmark,
    faAngleDown,
} from '@fortawesome/free-solid-svg-icons';
import { ReportLogPanel, type LogStep } from '../components/ReportLogPanel';

interface Summary { total: number; open: number; closed: number; high_count: number; avg_first_resp_hours: number; }
interface MTTR {
    avg_hours: number; median_hours: number; p90_hours: number; p95_hours: number;
    min_hours: number; max_hours: number; total_closed: number;
    by_severity: { severity: string; avg_hours: number; count: number }[];
}
interface DayPoint { date: string; High: number; Medium: number; Low: number; Informational: number; }
interface Owner { name: string; total: number; open: number; closed: number; }
interface SLA { severity: string; sla_target_hours: number; total: number; sla_met: number; sla_breached: number; compliance_rate: number; avg_mttr: number; }
interface Incident {
    number: number; title: string; severity: string; status: string; owner: string;
    created: string; closed: string; last_updated: string;
    classification: string; classification_comment: string;
    mttr_hours: number; tactics: string; description: string;
}
interface Recurrence {
    title: string; count: number; last_seen: string; first_seen: string;
    avg_mttr: number; severities: string[]; open_count: number;
}

type TabId = 'mttr' | 'trends' | 'owners' | 'sla' | 'incidents' | 'ai';

function sevColor(s: string) {
    if (s === 'High') return 'var(--critical)';
    if (s === 'Medium') return 'var(--high)';
    if (s === 'Low') return 'var(--low)';
    return 'var(--info)';
}

function sevBg(s: string) {
    if (s === 'High') return 'rgba(192,57,43,0.10)';
    if (s === 'Medium') return 'rgba(230,126,34,0.10)';
    if (s === 'Low') return 'rgba(39,174,96,0.10)';
    return 'rgba(52,152,219,0.10)';
}

function formatHours(h: number) {
    if (h < 1) return `${Math.round(h * 60)}m`;
    if (h < 48) return `${h.toFixed(1)}h`;
    return `${(h / 24).toFixed(1)}d`;
}

function fmtDate(iso: string) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }); }
    catch { return iso.slice(0, 16).replace('T', ' '); }
}

function renderMd(text: string): string {
    // ── Inline formatter ─────────────────────────────────────────────────────
    function inline(s: string): string {
        return s
            .replace(/\*\*(.+?)\*\*/g, '<strong style="color:var(--text-primary);font-weight:700">$1</strong>')
            .replace(/\*(.+?)\*/g, '<em style="color:var(--text-secondary)">$1</em>')
            .replace(/`([^`]+)`/g, '<code style="background:var(--bg-base,#f5f5f5);border:1px solid var(--border);border-radius:3px;padding:1px 5px;font-size:11px;font-family:monospace;color:var(--pwc-orange,#D04A02)">$1</code>');
    }

    // ── Table renderer ───────────────────────────────────────────────────────
    function renderTable(rows: string[][]): string {
        const sepIdx = rows.findIndex(r => r.every(c => /^:?-+:?$/.test(c.trim())));
        const O = 'var(--pwc-orange,#D04A02)';
        const B = 'var(--border,#e5e5e5)';

        if (sepIdx < 1) {
            // No header — body-only table
            const tbody = rows.map((r, ri) =>
                `<tr style="background:${ri % 2 === 0 ? 'rgba(208,74,2,0.025)' : 'transparent'}">` +
                r.map(c => `<td style="padding:7px 12px;border-bottom:1px solid ${B};font-size:12px;color:var(--text-secondary)">${inline(c)}</td>`).join('') +
                '</tr>'
            ).join('');
            return `<div style="overflow-x:auto;margin:10px 0;border:1px solid ${B};border-radius:6px;overflow:hidden"><table style="border-collapse:collapse;width:100%"><tbody>${tbody}</tbody></table></div>`;
        }

        const thead = rows.slice(0, sepIdx).map(r =>
            '<tr>' +
            r.map(c => `<th style="padding:8px 12px;border-bottom:2px solid ${O};background:rgba(208,74,2,0.06);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;color:var(--text-primary);text-align:left;white-space:nowrap">${inline(c)}</th>`).join('') +
            '</tr>'
        ).join('');

        const tbody = rows.slice(sepIdx + 1).map((r, ri) =>
            `<tr style="background:${ri % 2 === 0 ? 'rgba(208,74,2,0.02)' : 'transparent'};transition:background 0.1s" onmouseover="this.style.background='rgba(208,74,2,0.05)'" onmouseout="this.style.background='${ri % 2 === 0 ? 'rgba(208,74,2,0.02)' : 'transparent'}'">` +
            r.map(c => `<td style="padding:7px 12px;border-bottom:1px solid ${B};font-size:12px;color:var(--text-secondary);vertical-align:top">${inline(c)}</td>`).join('') +
            '</tr>'
        ).join('');

        return `<div style="overflow-x:auto;margin:10px 0;border:1px solid ${B};border-radius:6px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.06)"><table style="border-collapse:collapse;width:100%"><thead>${thead}</thead><tbody>${tbody}</tbody></table></div>`;
    }

    // ── Line-by-line parser ──────────────────────────────────────────────────
    const lines = text.split('\n');
    const out: string[] = [];
    let i = 0;
    const O = 'var(--pwc-orange,#D04A02)';

    while (i < lines.length) {
        const t = lines[i].trim();

        // Table block
        if (t.startsWith('|')) {
            const block: string[] = [];
            while (i < lines.length && lines[i].trim().startsWith('|')) { block.push(lines[i]); i++; }
            const rows = block.map(l => l.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim()));
            out.push(renderTable(rows));
            continue;
        }

        // Headings — check most-specific first
        if (/^### /.test(t)) {
            out.push(`<h4 style="margin:14px 0 5px;font-size:13px;font-weight:700;color:var(--text-primary)">${inline(t.slice(4))}</h4>`);
        } else if (/^## /.test(t)) {
            out.push(`<h3 style="margin:18px 0 6px;font-size:13px;font-weight:800;color:${O};text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid var(--border);padding-bottom:5px">${inline(t.slice(3))}</h3>`);
        } else if (/^# /.test(t)) {
            out.push(`<h2 style="margin:20px 0 8px;font-size:15px;font-weight:800;color:${O};border-bottom:2px solid var(--border);padding-bottom:6px">${inline(t.slice(2))}</h2>`);

        // Horizontal rule
        } else if (/^-{3,}$/.test(t) || /^\*{3,}$/.test(t)) {
            out.push('<hr style="border:none;border-top:1px solid var(--border);margin:12px 0">');

        // Numbered list
        } else if (/^\d+\.\s+/.test(t)) {
            const m = t.match(/^(\d+)\.\s+(.*)/s);
            const num = m ? m[1] : '1';
            const body = m ? m[2] : t;
            out.push(`<div style="display:flex;gap:8px;margin:4px 0;padding-left:4px;align-items:baseline"><span style="color:${O};font-weight:700;flex-shrink:0;min-width:20px;font-size:12px">${num}.</span><span style="color:var(--text-secondary);line-height:1.65">${inline(body)}</span></div>`);

        // Bullet
        } else if (/^[-*]\s+/.test(t)) {
            out.push(`<div style="display:flex;gap:8px;margin:3px 0;padding-left:4px;align-items:baseline"><span style="color:${O};flex-shrink:0;font-size:10px;margin-top:4px">▸</span><span style="color:var(--text-secondary);line-height:1.65">${inline(t.slice(2).trim())}</span></div>`);

        // Empty line
        } else if (t === '') {
            out.push('<div style="margin:5px 0"></div>');

        // Paragraph
        } else {
            out.push(`<p style="margin:3px 0;line-height:1.7;color:var(--text-secondary)">${inline(t)}</p>`);
        }

        i++;
    }

    return out.join('');
}

function MttrGauge({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
    const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
    return (
        <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>{label}</div>
            <div style={{ position: 'relative', width: 80, height: 80, margin: '0 auto' }}>
                <svg viewBox="0 0 80 80" style={{ transform: 'rotate(-90deg)' }}>
                    <circle cx="40" cy="40" r="32" fill="none" stroke="#f0f0f0" strokeWidth="8" />
                    <circle cx="40" cy="40" r="32" fill="none" stroke={color} strokeWidth="8"
                        strokeDasharray={`${pct * 2.01} 201`} strokeLinecap="round" />
                </svg>
                <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <div style={{ fontSize: 13, fontWeight: 800, color, lineHeight: 1 }}>{formatHours(value)}</div>
                </div>
            </div>
        </div>
    );
}

const AI_LOG_STEPS: LogStep[] = [
    { level: 'info', msg: 'Analysing incident volume and trends…',        delay: 500   },
    { level: 'info', msg: 'Evaluating MTTR and resolution patterns…',     delay: 2500  },
    { level: 'info', msg: 'Reviewing SLA compliance across severities…',  delay: 5000  },
    { level: 'info', msg: 'Assessing owner workload distribution…',       delay: 7500  },
    { level: 'info', msg: 'Identifying recurring incident patterns…',     delay: 10000 },
    { level: 'ai',   msg: 'Running LLM assessment with Claude…',          delay: 13000 },
    { level: 'ai',   msg: 'Generating priority recommendations…',         delay: 17000 },
];

interface EnrichmentData {
    source?: string;
    country?: string;
    org?: string;
    abuse_score?: number;
    abuse_reports?: number;
    flags?: string[];
    vt_malicious?: number;
    vt_suspicious?: number;
    vt_total?: number;
    vt_reputation?: number;
    vt_threat_label?: string;
    vt_meaningful_name?: string;
    vt_categories?: string[];
    shodan_ports?: number[];
    shodan_vulns?: string[];
}
type EntityDetail = { type: string; _enrichment?: EnrichmentData; [key: string]: string | EnrichmentData | undefined };
type AlertDetail = {
    time: string; name: string; description: string; severity: string;
    provider: string; tactics: string; entities: EntityDetail[]; extended: string;
};

function IncidentDetailModal({ incident, onClose }: { incident: Incident; onClose: () => void }) {
    type ModalTab = 'details' | 'entities' | 'alerts' | 'ai';
    const [modalTab, setModalTab]       = useState<ModalTab>('details');
    const [detailsData, setDetailsData] = useState<{
        entities: EntityDetail[];
        alerts: AlertDetail[];
        incident_metadata?: { tactics?: string; classification?: string; classification_comment?: string };
    } | null>(null);
    const [detailsLoading, setDetailsLoading] = useState(true);
    const [detailsError, setDetailsError]     = useState<string | null>(null);
    const [expandedAlert, setExpandedAlert]   = useState<number | null>(null);
    const [analyzing, setAnalyzing]   = useState(false);
    const [analysis, setAnalysis]     = useState('');
    const [analyzeError, setAnalyzeError] = useState<string | null>(null);

    const tacticStr = (t: unknown): string =>
        Array.isArray(t) ? (t as string[]).join(', ') : String(t ?? '');

    // Fetch entities + alerts when modal opens
    useEffect(() => {
        setDetailsLoading(true);
        setDetailsError(null);
        axios.get(`/api/incident-analytics/incidents/${incident.number}/details`, { timeout: 0 })
            .then(res => setDetailsData(res.data))
            .catch((e: any) => setDetailsError(e.response?.data?.detail || e.message || 'Failed to load details'))
            .finally(() => setDetailsLoading(false));
    }, [incident.number]);

    const handleAnalyze = async () => {
        setAnalyzing(true);
        setAnalyzeError(null);
        try {
            const res = await axios.post('/api/incident-analytics/analyze-incident', {
                incident,
                entities: detailsData?.entities ?? [],
            }, { timeout: 0 });
            setAnalysis(res.data.analysis || '');
        } catch (e: any) {
            setAnalyzeError(e.response?.data?.detail || e.message || 'Analysis failed');
        } finally {
            setAnalyzing(false);
        }
    };

    const ENTITY_ICON: Record<string, string> = {
        account: '👤', ip: '🌐', host: '💻', url: '🔗', uri: '🔗',
        file: '📄', process: '⚙️', mailbox: '📧', mailmessage: '✉️',
        registrykey: '🔑', registryvalue: '🔑', cloud: '☁️',
    };

    const meta = detailsData?.incident_metadata;
    const effectiveTactics        = meta?.tactics        || tacticStr(incident.tactics);
    const effectiveClassification = meta?.classification || incident.classification;
    const effectiveComment        = meta?.classification_comment || incident.classification_comment;

    const DETAIL_ROWS = [
        { label: 'Incident #',     value: String(incident.number) },
        { label: 'Owner',          value: incident.owner || 'Unassigned',                                             bold: true },
        { label: 'Created',        value: fmtDate(incident.created) },
        { label: 'Last Updated',   value: fmtDate(incident.last_updated) },
        { label: 'Closed',         value: incident.closed ? fmtDate(incident.closed) : 'Not yet closed',              muted: !incident.closed },
        { label: 'MTTR',           value: (incident.mttr_hours ?? 0) > 0 ? formatHours(incident.mttr_hours) + (incident.status !== 'Closed' ? ' (ongoing)' : '') : '—' },
        { label: 'Tactics',        value: effectiveTactics || '—',                                                    accent: !!effectiveTactics },
        { label: 'Classification', value: effectiveClassification || 'Unclassified',                                  muted: !effectiveClassification },
        { label: 'Comment',        value: effectiveComment || '—',                                                    muted: !effectiveComment },
    ] as { label: string; value: string; bold?: boolean; muted?: boolean; accent?: boolean }[];

    const TABS: { id: ModalTab; label: string }[] = [
        { id: 'details',  label: 'Details' },
        { id: 'entities', label: `Entities${detailsData ? ` (${detailsData.entities.length})` : ''}` },
        { id: 'alerts',   label: `Alerts${detailsData ? ` (${detailsData.alerts.length})` : ''}` },
        { id: 'ai',       label: 'AI Analysis' },
    ];

    const LoadingPane = ({ msg }: { msg: string }) => (
        <div style={{ textAlign: 'center', padding: '48px 0' }}>
            <span className="spinner" style={{ width: 24, height: 24 }} />
            <div style={{ marginTop: 12, color: 'var(--text-muted)', fontSize: 13 }}>{msg}</div>
        </div>
    );

    const ErrorPane = ({ msg }: { msg: string }) => (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', color: 'var(--critical)', fontSize: 13, padding: '24px 0' }}>
            <FontAwesomeIcon icon={faCircleXmark} /> {msg}
        </div>
    );

    const EmptyPane = ({ msg }: { msg: string }) => (
        <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontSize: 13 }}>{msg}</div>
    );

    return (
        <div
            style={{
                position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)',
                backdropFilter: 'blur(2px)', zIndex: 1000,
            }}
            onClick={onClose}
        >
            <div
                style={{
                    position: 'absolute', top: 0, right: 0, bottom: 0,
                    width: 820, maxWidth: '92vw',
                    background: 'var(--bg-card)', borderLeft: '1px solid var(--border)',
                    boxShadow: '-4px 0 32px rgba(0,0,0,0.35)',
                    display: 'flex', flexDirection: 'column', overflow: 'hidden',
                    animation: 'slideInRight 0.25s cubic-bezier(0.22,1,0.36,1)',
                }}
                onClick={e => e.stopPropagation()}
            >
            <style>{`@keyframes slideInRight { from { transform: translateX(100%); opacity: 0.4; } to { transform: translateX(0); opacity: 1; } }`}</style>
                {/* ── Sticky header ─────────────────────────────────────── */}
                <div style={{ padding: '18px 24px 0', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                        <div style={{ flex: 1, paddingRight: 16 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 3 }}>
                                <FontAwesomeIcon icon={faShieldHalved} style={{ color: 'var(--brand)', fontSize: 17, flexShrink: 0 }} />
                                <div style={{ fontSize: 15, fontWeight: 700, lineHeight: 1.3 }}>
                                    <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginRight: 8, fontSize: 13 }}>#{incident.number}</span>
                                    {incident.title}
                                </div>
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 27 }}>Microsoft Sentinel — Incident Details</div>
                        </div>
                        <button onClick={onClose}
                            style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 10px', cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)', flexShrink: 0 }}>
                            ✕
                        </button>
                    </div>

                    {/* Status badges */}
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
                        <span style={{ fontSize: 12, fontWeight: 700, color: sevColor(incident.severity), background: sevBg(incident.severity), padding: '3px 12px', borderRadius: 20 }}>{incident.severity}</span>
                        <span style={{ fontSize: 12, fontWeight: 700, padding: '3px 12px', borderRadius: 20, color: incident.status === 'Closed' ? 'var(--low)' : 'var(--critical)', background: incident.status === 'Closed' ? 'rgba(39,174,96,0.10)' : 'rgba(192,57,43,0.10)' }}>{incident.status}</span>
                        {(incident.mttr_hours ?? 0) > 0 && (
                            <span style={{ fontSize: 12, color: 'var(--text-muted)', padding: '3px 12px', background: 'var(--bg-base)', borderRadius: 20, border: '1px solid var(--border)' }}>
                                MTTR: {formatHours(incident.mttr_hours)}{incident.status !== 'Closed' ? ' (ongoing)' : ''}
                            </span>
                        )}
                    </div>

                    {/* Tab bar */}
                    <div style={{ display: 'flex', gap: 2 }}>
                        {TABS.map(t => (
                            <button key={t.id} onClick={() => setModalTab(t.id)} style={{
                                padding: '7px 16px', border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 600,
                                borderRadius: '6px 6px 0 0', transition: 'all 0.15s',
                                background: modalTab === t.id ? 'var(--bg-card)' : 'transparent',
                                color: modalTab === t.id ? 'var(--pwc-orange,var(--brand))' : 'var(--text-muted)',
                                borderBottom: modalTab === t.id ? '2px solid var(--pwc-orange,var(--brand))' : '2px solid transparent',
                            }}>
                                {t.label}
                            </button>
                        ))}
                    </div>
                </div>

                {/* ── Scrollable body ────────────────────────────────────── */}
                <div style={{ overflow: 'auto', flex: 1, padding: '20px 24px' }}>

                    {/* ── Details tab ───────────────────────────────── */}
                    {modalTab === 'details' && (
                        <>
                            <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', gap: 0, background: 'var(--bg-base)', borderRadius: 8, marginBottom: 16, border: '1px solid var(--border)', overflow: 'hidden', fontSize: 13 }}>
                                {DETAIL_ROWS.map((row, i) => (
                                    <div key={i} style={{ display: 'contents' }}>
                                        <div style={{ padding: '9px 14px', background: i % 2 === 0 ? 'rgba(0,0,0,0.02)' : 'transparent', borderTop: i > 0 ? '1px solid var(--border)' : 'none', color: 'var(--text-muted)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.04em', display: 'flex', alignItems: 'center' }}>{row.label}</div>
                                        <div style={{ padding: '9px 14px', background: i % 2 === 0 ? 'rgba(0,0,0,0.02)' : 'transparent', borderTop: i > 0 ? '1px solid var(--border)' : 'none', borderLeft: '1px solid var(--border)', color: row.accent ? 'var(--high)' : row.muted ? 'var(--text-muted)' : 'var(--text-primary)', fontWeight: row.bold ? 600 : 400, wordBreak: 'break-word' as const }}>{row.value}</div>
                                    </div>
                                ))}
                            </div>
                            {incident.description && (
                                <div>
                                    <div style={{ fontSize: 11, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Description</div>
                                    <div style={{ fontSize: 13, lineHeight: 1.65, color: 'var(--text-secondary)', background: 'var(--bg-base)', borderRadius: 8, padding: 14, border: '1px solid var(--border)' }}>
                                        {incident.description}
                                    </div>
                                </div>
                            )}
                        </>
                    )}

                    {/* ── Entities tab ──────────────────────────────── */}
                    {modalTab === 'entities' && (
                        detailsLoading ? <LoadingPane msg="Loading entities from Sentinel…" /> :
                        detailsError   ? <ErrorPane msg={detailsError} /> :
                        !detailsData?.entities.length ? (
                            <div style={{ textAlign: 'center', padding: '48px 0' }}>
                                <div style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 12 }}>No entities found for this incident</div>
                                <a
                                    href={`/api/incident-analytics/incidents/${incident.number}/debug`}
                                    target="_blank"
                                    rel="noreferrer"
                                    style={{ fontSize: 11, color: 'var(--brand)', textDecoration: 'underline', cursor: 'pointer' }}
                                >
                                    View raw Sentinel data (debug)
                                </a>
                            </div>
                        ) : (
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(230px, 1fr))', gap: 12 }}>
                                {detailsData.entities.map((entity, i) => {
                                    const icon = ENTITY_ICON[entity.type?.toLowerCase()] ?? '🔷';
                                    const { type, _enrichment, ...fields } = entity;
                                    const enr = _enrichment as EnrichmentData | undefined;
                                    const mal = enr?.vt_malicious ?? 0;
                                    const vtTotal = enr?.vt_total ?? 0;
                                    const abuseScore = enr?.abuse_score ?? 0;
                                    const threatLevel = mal > 5 || abuseScore > 70 ? 'critical'
                                        : mal > 0 || abuseScore > 20 ? 'warning'
                                        : enr ? 'clean' : null;
                                    const threatColor = threatLevel === 'critical' ? 'var(--critical)'
                                        : threatLevel === 'warning' ? 'var(--high)' : 'var(--low)';
                                    const borderColor = threatLevel ? threatColor : 'var(--brand)';
                                    return (
                                        <div key={i} style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 8, padding: 14, borderLeft: `3px solid ${borderColor}` }}>
                                            {/* Header */}
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, paddingBottom: 8, borderBottom: '1px solid var(--border)' }}>
                                                <span style={{ fontSize: 18 }}>{icon}</span>
                                                <span style={{ fontSize: 11, fontWeight: 800, color: 'var(--brand)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{type as string}</span>
                                                {threatLevel && (
                                                    <span style={{ marginLeft: 'auto', fontSize: 9, fontWeight: 800, color: threatColor, background: `color-mix(in srgb, ${threatColor} 12%, transparent)`, padding: '2px 6px', borderRadius: 8, whiteSpace: 'nowrap' }}>
                                                        {threatLevel === 'critical' ? '⚠ HIGH RISK' : threatLevel === 'warning' ? '⚠ SUSPICIOUS' : '✓ CLEAN'}
                                                    </span>
                                                )}
                                            </div>
                                            {/* String fields */}
                                            {Object.entries(fields).filter(([, v]) => v && typeof v === 'string').map(([k, v]) => (
                                                <div key={k} style={{ marginBottom: 6 }}>
                                                    <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 1 }}>{k}</div>
                                                    <div style={{ fontSize: 12, color: 'var(--text-primary)', wordBreak: 'break-all' }}>{v as string}</div>
                                                </div>
                                            ))}
                                            {/* Enrichment section */}
                                            {enr && (
                                                <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px dashed var(--border)' }}>
                                                    <div style={{ fontSize: 9, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                                                        Threat Intelligence · {enr.source}
                                                    </div>
                                                    {/* VT detection bar */}
                                                    {vtTotal > 0 && (
                                                        <div style={{ marginBottom: 8 }}>
                                                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                                                                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>VirusTotal</span>
                                                                <span style={{ fontSize: 10, fontWeight: 800, color: mal > 5 ? 'var(--critical)' : mal > 0 ? 'var(--high)' : 'var(--low)' }}>
                                                                    {mal}/{vtTotal} malicious
                                                                </span>
                                                            </div>
                                                            <div style={{ background: 'var(--border)', borderRadius: 3, height: 4, overflow: 'hidden' }}>
                                                                <div style={{ background: mal > 5 ? 'var(--critical)' : mal > 0 ? 'var(--high)' : 'var(--low)', width: `${vtTotal > 0 ? Math.round((mal / vtTotal) * 100) : 0}%`, height: '100%', transition: 'width 0.4s' }} />
                                                            </div>
                                                            {(enr.vt_suspicious ?? 0) > 0 && (
                                                                <div style={{ fontSize: 10, color: 'var(--high)', marginTop: 2 }}>{enr.vt_suspicious} suspicious</div>
                                                            )}
                                                        </div>
                                                    )}
                                                    {/* AbuseIPDB */}
                                                    {abuseScore > 0 && (
                                                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                                                            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>AbuseIPDB</span>
                                                            <span style={{ fontSize: 10, fontWeight: 800, color: abuseScore > 70 ? 'var(--critical)' : abuseScore > 20 ? 'var(--high)' : 'var(--text-secondary)' }}>
                                                                {abuseScore}/100 ({enr.abuse_reports} reports)
                                                            </span>
                                                        </div>
                                                    )}
                                                    {/* Flags */}
                                                    {(enr.flags?.length ?? 0) > 0 && (
                                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginBottom: 6 }}>
                                                            {enr.flags!.map(f => (
                                                                <span key={f} style={{ fontSize: 9, fontWeight: 800, padding: '2px 6px', borderRadius: 8, background: 'rgba(208,74,2,0.10)', color: 'var(--brand)' }}>{f}</span>
                                                            ))}
                                                        </div>
                                                    )}
                                                    {/* Country / Org */}
                                                    {(enr.country || enr.org) && (
                                                        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>
                                                            {[enr.country, enr.org].filter(Boolean).join(' · ')}
                                                        </div>
                                                    )}
                                                    {/* Shodan ports */}
                                                    {(enr.shodan_ports?.length ?? 0) > 0 && (
                                                        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>
                                                            Ports: {enr.shodan_ports!.join(', ')}
                                                        </div>
                                                    )}
                                                    {/* CVEs */}
                                                    {(enr.shodan_vulns?.length ?? 0) > 0 && (
                                                        <div style={{ fontSize: 10, color: 'var(--critical)', fontWeight: 700, marginBottom: 4 }}>
                                                            CVEs: {enr.shodan_vulns!.join(', ')}
                                                        </div>
                                                    )}
                                                    {/* VT threat label (file hashes) */}
                                                    {enr.vt_threat_label && (
                                                        <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--critical)', marginBottom: 2 }}>
                                                            Threat: {enr.vt_threat_label}
                                                        </div>
                                                    )}
                                                    {enr.vt_meaningful_name && (
                                                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>File: {enr.vt_meaningful_name}</div>
                                                    )}
                                                    {/* VT categories (domains) */}
                                                    {(enr.vt_categories?.length ?? 0) > 0 && (
                                                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                                                            Categories: {enr.vt_categories!.join(', ')}
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        )
                    )}

                    {/* ── Alerts tab ────────────────────────────────── */}
                    {modalTab === 'alerts' && (
                        detailsLoading ? <LoadingPane msg="Loading related alerts from Sentinel…" /> :
                        detailsError   ? <ErrorPane msg={detailsError} /> :
                        !detailsData?.alerts.length ? <EmptyPane msg="No related security alerts found for this incident" /> : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                {detailsData.alerts.map((alert, i) => (
                                    <div key={i} style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden', borderLeft: `3px solid ${sevColor(alert.severity)}` }}>
                                        {/* Alert header row — always visible */}
                                        <div style={{ padding: '12px 14px', cursor: 'pointer', display: 'flex', alignItems: 'flex-start', gap: 10 }} onClick={() => setExpandedAlert(expandedAlert === i ? null : i)}>
                                            <div style={{ flex: 1 }}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                                                    <span style={{ fontSize: 11, fontWeight: 700, color: sevColor(alert.severity), background: sevBg(alert.severity), padding: '2px 8px', borderRadius: 10 }}>{alert.severity}</span>
                                                    {alert.provider && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{alert.provider}</span>}
                                                    {alert.tactics && <span style={{ fontSize: 11, color: 'var(--high)', fontWeight: 600 }}>{alert.tactics}</span>}
                                                    <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>{fmtDate(alert.time)}</span>
                                                </div>
                                                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{alert.name}</div>
                                            </div>
                                            <span style={{ color: 'var(--text-muted)', fontSize: 11, flexShrink: 0, marginTop: 4 }}>{expandedAlert === i ? '▲' : '▼'}</span>
                                        </div>

                                        {/* Expanded alert detail */}
                                        {expandedAlert === i && (
                                            <div style={{ borderTop: '1px solid var(--border)', padding: '14px 14px 14px' }}>
                                                {alert.description && (
                                                    <div style={{ marginBottom: 14 }}>
                                                        <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 5 }}>Description</div>
                                                        <div style={{ fontSize: 12, lineHeight: 1.65, color: 'var(--text-secondary)' }}>{alert.description}</div>
                                                    </div>
                                                )}
                                                {alert.entities.length > 0 && (
                                                    <div style={{ marginBottom: 14 }}>
                                                        <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>Entities ({alert.entities.length})</div>
                                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                                            {alert.entities.map((e, j) => {
                                                                const icon = ENTITY_ICON[e.type?.toLowerCase()] ?? '🔷';
                                                                const label = String(e.Address || e.Name || e.Hostname || e.URL || e.Subject || Object.values(e).find((v): v is string => typeof v === 'string' && v !== e.type) || e.type);
                                                                return (
                                                                    <span key={j} title={JSON.stringify(e, null, 2)} style={{ fontSize: 11, padding: '3px 10px', borderRadius: 12, background: 'rgba(208,74,2,0.07)', color: 'var(--text-secondary)', border: '1px solid rgba(208,74,2,0.15)', cursor: 'default' }}>
                                                                        {icon} {label}
                                                                    </span>
                                                                );
                                                            })}
                                                        </div>
                                                    </div>
                                                )}
                                                {alert.extended && alert.extended !== '{}' && alert.extended !== '' && (
                                                    <div>
                                                        <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 5 }}>Extended Properties</div>
                                                        <pre style={{ fontSize: 11, color: 'var(--text-secondary)', background: 'var(--bg-card)', padding: 10, borderRadius: 6, overflow: 'auto', maxHeight: 200, margin: 0, border: '1px solid var(--border)', fontFamily: 'monospace' }}>
                                                            {(() => { try { return JSON.stringify(JSON.parse(alert.extended), null, 2); } catch { return alert.extended; } })()}
                                                        </pre>
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        )
                    )}

                    {/* ── AI Analysis tab ───────────────────────────── */}
                    {modalTab === 'ai' && (
                        <div>
                            {!analysis && (
                                <button disabled={analyzing} onClick={handleAnalyze} style={{ width: '100%', padding: '10px 16px', borderRadius: 8, background: analyzing ? 'rgba(208,74,2,0.08)' : 'var(--pwc-orange,var(--brand))', border: analyzing ? '1px solid var(--brand)' : 'none', color: analyzing ? 'var(--brand)' : '#fff', fontSize: 13, fontWeight: 700, cursor: analyzing ? 'default' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                                    {analyzing ? <><span className="spinner" style={{ width: 14, height: 14 }} /> Analyzing incident…</> : <><FontAwesomeIcon icon={faWandMagicSparkles} /> Analyze with AI &amp; Get Recommendations</>}
                                </button>
                            )}
                            {analyzeError && (
                                <div style={{ display: 'flex', gap: 8, alignItems: 'center', color: 'var(--critical)', fontSize: 12, marginTop: 10 }}>
                                    <FontAwesomeIcon icon={faCircleXmark} /> {analyzeError}
                                </div>
                            )}
                            {analysis && (
                                <div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 700, fontSize: 13, color: 'var(--text-primary)' }}>
                                            <FontAwesomeIcon icon={faRobot} style={{ color: 'var(--brand)' }} /> AI Analysis &amp; Recommendations
                                        </div>
                                        <button onClick={handleAnalyze} disabled={analyzing} style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 10px', cursor: 'pointer', fontSize: 11, color: 'var(--text-secondary)' }}>
                                            {analyzing ? <span className="spinner" style={{ width: 10, height: 10 }} /> : '↻ Re-analyze'}
                                        </button>
                                    </div>
                                    <div style={{ background: 'linear-gradient(135deg,rgba(208,74,2,0.03) 0%,rgba(208,74,2,0.01) 100%)', border: '1px solid rgba(208,74,2,0.15)', borderLeft: '3px solid var(--brand)', borderRadius: 8, padding: 16, fontSize: 13, lineHeight: 1.7, color: 'var(--text-secondary)' }}
                                        dangerouslySetInnerHTML={{ __html: renderMd(analysis) }} />
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}



export default function IncidentAnalytics() {
    const [tab, setTab] = useState<TabId>('mttr');
    const [days, setDays] = useState(30);
    const [summary, setSummary] = useState<Summary | null>(null);
    const [mttr, setMttr] = useState<MTTR | null>(null);
    const [trends, setTrends] = useState<DayPoint[]>([]);
    const [owners, setOwners] = useState<Owner[]>([]);
    const [sla, setSla] = useState<SLA[]>([]);
    const [incidents, setIncidents] = useState<Incident[]>([]);
    const [recurrence, setRecurrence] = useState<Recurrence[]>([]);
    const [loading, setLoading] = useState(true);
    const [isExporting, setIsExporting] = useState(false);
    const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);

    // Incidents tab filters
    const [search, setSearch] = useState('');
    const [statusFilter, setStatusFilter] = useState<'all' | 'open' | 'closed'>('all');
    const [sevFilter, setSevFilter] = useState('all');

    const [incidentsError, setIncidentsError] = useState<string | null>(null);

    // AI Assessment
    const [aiLoading, setAiLoading] = useState(false);
    const [aiSuccess, setAiSuccess] = useState<boolean | null>(null);
    const [aiError, setAiError] = useState<string | null>(null);
    const [assessment, setAssessment] = useState<string>('');

    const fetchData = async () => {
        setLoading(true);
        setIncidentsError(null);
        // allSettled ensures a single failing endpoint never silences the rest
        const results = await Promise.allSettled([
            axios.get(`/api/incident-analytics/summary?days=${days}`,    { timeout: 0 }),
            axios.get(`/api/incident-analytics/mttr?days=${days}`,       { timeout: 0 }),
            axios.get(`/api/incident-analytics/trends?days=${days}`,     { timeout: 0 }),
            axios.get(`/api/incident-analytics/owners?days=${days}`,     { timeout: 0 }),
            axios.get(`/api/incident-analytics/sla?days=${days}`,        { timeout: 0 }),
            axios.get(`/api/incident-analytics/incidents?days=${days}`,  { timeout: 0 }),
            axios.get(`/api/incident-analytics/recurrence?days=${days}`, { timeout: 0 }),
        ]);
        const ok = (i: number) =>
            results[i].status === 'fulfilled'
                ? (results[i] as PromiseFulfilledResult<any>).value.data
                : null;
        const [sum, mt, tr, ow, sl, inc, rec] = results.map((_, i) => ok(i));
        if (sum) setSummary(sum);
        if (mt)  setMttr(mt);
        if (tr)  setTrends(tr.daily   || []);
        if (ow)  setOwners(ow.owners  || []);
        if (sl)  setSla(sl.sla        || []);
        if (inc) {
            setIncidents(inc.incidents || []);
        } else {
            const r5 = results[5] as PromiseRejectedResult;
            const detail = r5?.reason?.response?.data?.detail || r5?.reason?.message || 'Incidents endpoint returned an error';
            setIncidentsError(detail);
            setIncidents([]);
        }
        if (rec) setRecurrence(rec.recurrent || []);
        setLoading(false);
    };

    useEffect(() => {
        setStatusFilter('all');
        setSevFilter('all');
        setSearch('');
        setIncidentsError(null);
        fetchData();
    }, [days]);

    const maxOwner = Math.max(...owners.map(o => o.total), 1);
    const maxTrend = Math.max(...trends.map(d => d.High + d.Medium + d.Low + d.Informational), 1);
    const mttrMax  = Math.max(mttr?.p95_hours ?? 1, 1);

    const overallSlaCompliance = useMemo(() => {
        if (!sla.length) return null;
        const totalMet = sla.reduce((a, s) => a + s.sla_met, 0);
        const total    = sla.reduce((a, s) => a + s.total, 0);
        return total > 0 ? Math.round((totalMet / total) * 100) : null;
    }, [sla]);

    const totalSlaBreached = useMemo(() => sla.reduce((a, s) => a + s.sla_breached, 0), [sla]);

    const tacticStr = (t: unknown): string =>
        Array.isArray(t) ? (t as string[]).join(', ') : String(t ?? '');

    const filteredIncidents = useMemo(() => {
        let list = incidents;
        if (statusFilter === 'open')   list = list.filter(i => ['Active', 'New'].includes(i.status));
        if (statusFilter === 'closed') list = list.filter(i => i.status === 'Closed');
        if (sevFilter !== 'all')       list = list.filter(i => i.severity === sevFilter);
        if (search.trim()) {
            const q = search.toLowerCase();
            list = list.filter(i =>
                i.title.toLowerCase().includes(q) ||
                String(i.number).includes(q) ||
                (i.owner || '').toLowerCase().includes(q) ||
                tacticStr(i.tactics).toLowerCase().includes(q)
            );
        }
        return list;
    }, [incidents, statusFilter, sevFilter, search]);

    const openCount   = useMemo(() => incidents.filter(i => ['Active', 'New'].includes(i.status)).length, [incidents]);
    const closedCount = useMemo(() => incidents.filter(i => i.status === 'Closed').length, [incidents]);

    const runAiAssessment = async () => {
        setAiLoading(true);
        setAiSuccess(null);
        setAiError(null);
        setAssessment('');
        try {
            const res = await axios.post('/api/incident-analytics/llm-assessment', {
                days,
                summary:    summary ?? {},
                mttr:       mttr ?? {},
                sla,
                owners,
                trends,
                recurrence,
            }, { timeout: 0 });
            setAssessment(res.data.assessment || '');
            setAiSuccess(true);
        } catch (e: any) {
            setAiError(e.response?.data?.detail || e.message || 'Assessment failed');
            setAiSuccess(false);
        } finally {
            setAiLoading(false);
        }
    };

    const handleExport = async (format: 'pdf' | 'html') => {
        setIsExporting(true);
        const html = `<div style="font-family:Inter,sans-serif;padding:40px;color:#2D2D2D">
            <h1 style="color:#D04A02;border-bottom:3px solid #D04A02;padding-bottom:16px">Incident Analytics Report</h1>
            <p>Period: Last ${days} days · Generated: ${new Date().toLocaleString()}</p>
            <h2>Summary</h2>
            <p>Total: <strong>${summary?.total}</strong> · Open: <strong>${summary?.open}</strong> · Closed: <strong>${summary?.closed}</strong> · High: <strong>${summary?.high_count}</strong></p>
            <h2>MTTR Summary</h2>
            <p>Avg: <strong>${formatHours(mttr?.avg_hours ?? 0)}</strong> · Median: <strong>${formatHours(mttr?.median_hours ?? 0)}</strong> · P90: <strong>${formatHours(mttr?.p90_hours ?? 0)}</strong></p>
            <h2>SLA Compliance</h2>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#F7F7F7">
                    <th style="padding:10px;border:1px solid #E5E5E5;text-align:left">Severity</th>
                    <th style="padding:10px;border:1px solid #E5E5E5">SLA Target</th>
                    <th style="padding:10px;border:1px solid #E5E5E5">Met</th>
                    <th style="padding:10px;border:1px solid #E5E5E5">Breached</th>
                    <th style="padding:10px;border:1px solid #E5E5E5">Rate</th>
                </tr>
                ${sla.map(r => `<tr>
                    <td style="padding:8px;border:1px solid #E5E5E5">${r.severity}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;text-align:center">${r.sla_target_hours}h</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;color:#27AE60;text-align:center">${r.sla_met}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;color:#C0392B;text-align:center">${r.sla_breached}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;font-weight:700;text-align:center">${r.compliance_rate}%</td>
                </tr>`).join('')}
            </table></div>`;
        try {
            const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const res = await axios.post(endpoint, { html, filename: `Incident_Analytics_${days}d.${format}` }, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url; a.download = `Incident_Analytics.${format}`; a.click(); a.remove();
        } catch (e: any) { alert(`Export failed: ${e.message}`); }
        finally { setIsExporting(false); }
    };

    const Skeleton = () => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 14 }}>
                {[1,2,3,4,5,6].map(i => <div key={i} className="stat-tile"><div className="skeleton skeleton-title" /><div className="skeleton skeleton-text" /></div>)}
            </div>
            <div className="card"><div className="skeleton skeleton-box" style={{ height: 240 }} /></div>
        </div>
    );

    const TABS: { id: TabId; label: string; icon: any }[] = [
        { id: 'mttr',      label: 'MTTR Analysis',   icon: faClock         },
        { id: 'trends',    label: 'Daily Trends',     icon: faChartBar      },
        { id: 'owners',    label: 'Owner Workload',   icon: faUsers         },
        { id: 'sla',       label: 'SLA Compliance',   icon: faShieldHalved  },
        { id: 'incidents', label: 'Incidents',        icon: faList          },
        { id: 'ai',        label: 'AI Assessment',    icon: faRobot         },
    ];

    return (
        <>
        <div>
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faChartBar} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Incident Analytics
                        </div>
                        <div className="page-subtitle">Comprehensive incident overview — MTTR, SLA, trends, owner workload, and AI recommendations</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <button className="btn btn-sm btn-ghost" onClick={() => handleExport('html')} disabled={isExporting || loading}>
                            <FontAwesomeIcon icon={faFileCode} style={{ color: 'var(--info)' }} /> HTML
                        </button>
                        <button className="btn btn-sm btn-ghost" onClick={() => handleExport('pdf')} disabled={isExporting || loading}>
                            <FontAwesomeIcon icon={faFilePdf} style={{ color: 'var(--critical)' }} /> PDF
                        </button>
                        <button className="btn btn-sm btn-ghost" onClick={fetchData} disabled={loading}>
                            <FontAwesomeIcon icon={faRefresh} spin={loading} /> Refresh
                        </button>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-card)', padding: '4px 12px', borderRadius: 8, border: '1px solid var(--border-color)' }}>
                            <span style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Period</span>
                            <select value={days} onChange={e => setDays(Number(e.target.value))} disabled={loading}
                                style={{ background: 'none', border: 'none', color: 'var(--pwc-orange)', fontSize: 13, fontWeight: 700, cursor: 'pointer', outline: 'none', padding: '4px 0' }}>
                                <option value={7}>7 Days</option>
                                <option value={30}>30 Days</option>
                                <option value={90}>90 Days</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <div className="page-content">
                {loading ? <Skeleton /> : (
                    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

                        {/* ── KPI Row ── */}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 14 }}>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--brand)' }}>
                                <div className="stat-tile-label">Total Incidents</div>
                                <div className="stat-tile-value">{(summary?.total ?? 0).toLocaleString()}</div>
                                <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                                    <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--critical)', fontWeight: 700 }}>
                                        <FontAwesomeIcon icon={faCircleXmark} style={{ fontSize: 10 }} />{summary?.open ?? 0} open
                                    </span>
                                    <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--low)', fontWeight: 700 }}>
                                        <FontAwesomeIcon icon={faCircleCheck} style={{ fontSize: 10 }} />{summary?.closed ?? 0} closed
                                    </span>
                                </div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--critical)' }}>
                                <div className="stat-tile-label">High Severity</div>
                                <div className="stat-tile-value" style={{ color: 'var(--critical)' }}>{(summary?.high_count ?? 0).toLocaleString()}</div>
                                <div className="text-xs text-muted">Immediate escalation</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--info)' }}>
                                <div className="stat-tile-label">Avg MTTR</div>
                                <div className="stat-tile-value" style={{ color: 'var(--info)', fontSize: 22 }}>{formatHours(mttr?.avg_hours ?? 0)}</div>
                                <div className="text-xs text-muted">Median {formatHours(mttr?.median_hours ?? 0)}</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--high)' }}>
                                <div className="stat-tile-label">P90 MTTR</div>
                                <div className="stat-tile-value" style={{ color: 'var(--high)', fontSize: 22 }}>{formatHours(mttr?.p90_hours ?? 0)}</div>
                                <div className="text-xs text-muted">90th percentile</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: `3px solid ${overallSlaCompliance !== null && overallSlaCompliance < 70 ? 'var(--critical)' : 'var(--low)'}` }}>
                                <div className="stat-tile-label">SLA Compliance</div>
                                <div className="stat-tile-value" style={{ color: overallSlaCompliance !== null && overallSlaCompliance < 70 ? 'var(--critical)' : 'var(--low)', fontSize: 22 }}>
                                    {overallSlaCompliance !== null ? `${overallSlaCompliance}%` : '—'}
                                </div>
                                <div className="text-xs text-muted">{totalSlaBreached} breached</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--brand)' }}>
                                <div className="stat-tile-label">Recurring</div>
                                <div className="stat-tile-value" style={{ color: recurrence.length > 0 ? 'var(--high)' : 'var(--text-muted)', fontSize: 22 }}>{recurrence.length}</div>
                                <div className="text-xs text-muted">Repeat incident titles</div>
                            </div>
                        </div>

                        {/* ── Tabs ── */}
                        <div className="tabs" style={{ marginBottom: 0 }}>
                            {TABS.map(t => (
                                <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                                    <FontAwesomeIcon icon={t.icon} style={{ marginRight: 8 }} />{t.label}
                                    {t.id === 'incidents' && incidents.length > 0 && (
                                        <span style={{ marginLeft: 6, background: 'var(--brand)', color: '#fff', borderRadius: 10, fontSize: 10, fontWeight: 700, padding: '1px 6px' }}>
                                            {incidents.length}
                                        </span>
                                    )}
                                </button>
                            ))}
                        </div>

                        {/* ── MTTR ── */}
                        {tab === 'mttr' && (
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20 }}>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faClock} className="card-title-icon" />
                                        MTTR Percentile Distribution
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-around', padding: '20px 0 10px', flexWrap: 'wrap', gap: 16 }}>
                                        <MttrGauge label="Min"          value={mttr?.min_hours ?? 0}    max={mttrMax} color="var(--low)"      />
                                        <MttrGauge label="Avg"          value={mttr?.avg_hours ?? 0}    max={mttrMax} color="var(--info)"     />
                                        <MttrGauge label="Median (P50)" value={mttr?.median_hours ?? 0} max={mttrMax} color="var(--brand)"    />
                                        <MttrGauge label="P90"          value={mttr?.p90_hours ?? 0}    max={mttrMax} color="var(--high)"     />
                                        <MttrGauge label="P95"          value={mttr?.p95_hours ?? 0}    max={mttrMax} color="var(--critical)" />
                                        <MttrGauge label="Max"          value={mttr?.max_hours ?? 0}    max={mttrMax} color="#7D7D7D"         />
                                    </div>
                                    <div style={{ textAlign: 'center', marginTop: 8, fontSize: 11, color: 'var(--text-muted)' }}>
                                        Based on {(mttr?.total_closed ?? 0).toLocaleString()} closed incidents
                                    </div>
                                </div>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faArrowTrendDown} className="card-title-icon" />
                                        MTTR by Severity
                                    </div>
                                    {(mttr?.by_severity ?? []).length === 0 ? (
                                        <div className="empty-state"><div className="empty-state-text">No MTTR data by severity</div></div>
                                    ) : (
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                                            {(mttr?.by_severity ?? []).map(s => (
                                                <div key={s.severity}>
                                                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
                                                        <span style={{ fontWeight: 700, color: sevColor(s.severity) }}>{s.severity}</span>
                                                        <span style={{ color: 'var(--text-muted)' }}>{formatHours(s.avg_hours)} avg · {s.count} incidents</span>
                                                    </div>
                                                    <div style={{ height: 10, background: '#f5f5f5', borderRadius: 5 }}>
                                                        <div style={{ width: `${Math.min((s.avg_hours / mttrMax) * 100, 100)}%`, height: '100%', background: sevColor(s.severity), borderRadius: 5, transition: 'width 0.5s' }} />
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* ── Daily Trends ── */}
                        {tab === 'trends' && (
                            <div className="card">
                                <div className="card-title">
                                    <FontAwesomeIcon icon={faChartBar} className="card-title-icon" />
                                    Daily Incident Creation by Severity
                                </div>
                                <div style={{ display: 'flex', gap: 16, marginBottom: 12, flexWrap: 'wrap' }}>
                                    {[
                                        { label: 'High', color: 'var(--critical)' },
                                        { label: 'Medium', color: 'var(--high)' },
                                        { label: 'Low', color: 'var(--low)' },
                                        { label: 'Informational', color: 'var(--info)' },
                                    ].map(s => (
                                        <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                            <div style={{ width: 10, height: 10, borderRadius: 2, background: s.color }} />{s.label}
                                        </div>
                                    ))}
                                </div>
                                {trends.length === 0 ? (
                                    <div className="empty-state"><div className="empty-state-text">No trend data</div></div>
                                ) : (
                                    <div>
                                        <div style={{ height: 220, display: 'flex', alignItems: 'flex-end', gap: 3, paddingBottom: 6 }}>
                                            {trends.map((d, i) => {
                                                const total = d.High + d.Medium + d.Low + d.Informational;
                                                const h = (total / maxTrend) * 200;
                                                return (
                                                    <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', height: `${Math.max(h, 2)}px`, borderRadius: '3px 3px 0 0', overflow: 'hidden', cursor: 'default' }}
                                                        title={`${d.date}\nH:${d.High}  M:${d.Medium}  L:${d.Low}  I:${d.Informational}`}>
                                                        <div style={{ flex: d.Informational, background: 'var(--info)', minHeight: d.Informational > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.Low,           background: 'var(--low)',      minHeight: d.Low > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.Medium,        background: 'var(--high)',     minHeight: d.Medium > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.High,          background: 'var(--critical)', minHeight: d.High > 0 ? 1 : 0 }} />
                                                    </div>
                                                );
                                            })}
                                        </div>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)' }}>
                                            <span>{trends[0]?.date}</span>
                                            <span>{trends[trends.length - 1]?.date}</span>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* ── Owners ── */}
                        {tab === 'owners' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faUsers} className="card-title-icon" />
                                        Incident Workload by Owner
                                    </div>
                                </div>
                                {owners.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}><div className="empty-state-text">No owner data available</div></div>
                                ) : (
                                    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
                                        {owners.map(o => (
                                            <div key={o.name} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                                                <div style={{ width: 200, fontSize: 12, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0 }}
                                                    title={o.name}>{o.name}</div>
                                                <div style={{ flex: 1, height: 22, background: '#f5f5f5', borderRadius: 4, overflow: 'hidden', position: 'relative' }}>
                                                    <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: `${(o.total / maxOwner) * 100}%`, background: 'linear-gradient(90deg, var(--brand) 0%, #ff8c42 100%)', borderRadius: 4, transition: 'width 0.5s' }} />
                                                    <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', paddingLeft: 8, fontSize: 11, color: '#fff', fontWeight: 700, zIndex: 1 }}>
                                                        {o.total}
                                                    </div>
                                                </div>
                                                <div style={{ display: 'flex', gap: 12, fontSize: 11, flexShrink: 0, width: 120 }}>
                                                    <span style={{ color: 'var(--critical)' }}>{o.open} open</span>
                                                    <span style={{ color: 'var(--text-muted)' }}>{o.closed} closed</span>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* ── SLA ── */}
                        {tab === 'sla' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, alignItems: 'center' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" style={{ color: 'var(--brand)' }} />
                                        SLA Compliance (High=4h, Medium=8h, Low=24h, Info=72h)
                                    </div>
                                </div>
                                {sla.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}><div className="empty-state-text">No SLA data available</div></div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Severity</th>
                                                    <th style={{ width: 110 }}>SLA Target</th>
                                                    <th style={{ width: 80 }}>Total</th>
                                                    <th style={{ width: 80 }}>Met</th>
                                                    <th style={{ width: 90 }}>Breached</th>
                                                    <th style={{ width: 100 }}>Avg MTTR</th>
                                                    <th>Compliance</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {sla.map(r => (
                                                    <tr key={r.severity}>
                                                        <td style={{ fontWeight: 700, color: sevColor(r.severity) }}>{r.severity}</td>
                                                        <td style={{ fontSize: 12 }}>{r.sla_target_hours}h</td>
                                                        <td>{r.total}</td>
                                                        <td style={{ color: 'var(--low)', fontWeight: 600 }}>{r.sla_met}</td>
                                                        <td style={{ color: r.sla_breached > 0 ? 'var(--critical)' : 'var(--text-muted)', fontWeight: 600 }}>{r.sla_breached}</td>
                                                        <td style={{ fontSize: 12 }}>{formatHours(r.avg_mttr)}</td>
                                                        <td style={{ width: 220 }}>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                                <div style={{ flex: 1, height: 10, background: '#f5f5f5', borderRadius: 5 }}>
                                                                    <div style={{ width: `${r.compliance_rate}%`, height: '100%', background: r.compliance_rate >= 80 ? 'var(--low)' : r.compliance_rate >= 50 ? 'var(--high)' : 'var(--critical)', borderRadius: 5 }} />
                                                                </div>
                                                                <span style={{ fontSize: 12, fontWeight: 700, color: r.compliance_rate >= 80 ? 'var(--low)' : 'var(--critical)', minWidth: 42 }}>{r.compliance_rate}%</span>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* ── Incidents ── */}
                        {tab === 'incidents' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                {/* Count header */}
                                <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                                    <div style={{ display: 'flex', gap: 8 }}>
                                        {(['all', 'open', 'closed'] as const).map(f => (
                                            <button key={f} onClick={() => setStatusFilter(f)}
                                                style={{
                                                    padding: '5px 14px', borderRadius: 20, border: '1px solid var(--border)',
                                                    background: statusFilter === f ? 'var(--brand)' : 'var(--bg-card)',
                                                    color: statusFilter === f ? '#fff' : 'var(--text-secondary)',
                                                    fontSize: 12, fontWeight: 700, cursor: 'pointer', transition: 'all 0.15s',
                                                }}>
                                                {f === 'all' ? `All (${incidents.length})` : f === 'open' ? `Open (${openCount})` : `Closed (${closedCount})`}
                                            </button>
                                        ))}
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '5px 10px' }}>
                                        <FontAwesomeIcon icon={faFilter} style={{ fontSize: 10, color: 'var(--text-muted)' }} />
                                        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
                                            style={{ background: 'none', border: 'none', fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer', outline: 'none' }}>
                                            <option value="all">All Severities</option>
                                            <option value="High">High</option>
                                            <option value="Medium">Medium</option>
                                            <option value="Low">Low</option>
                                            <option value="Informational">Informational</option>
                                        </select>
                                        <FontAwesomeIcon icon={faAngleDown} style={{ fontSize: 10, color: 'var(--text-muted)' }} />
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, maxWidth: 360, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '5px 12px' }}>
                                        <FontAwesomeIcon icon={faSearch} style={{ fontSize: 11, color: 'var(--text-muted)' }} />
                                        <input value={search} onChange={e => setSearch(e.target.value)}
                                            placeholder="Search title, owner, tactics…"
                                            style={{ background: 'none', border: 'none', outline: 'none', fontSize: 12, color: 'var(--text-primary)', width: '100%' }} />
                                    </div>
                                    <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
                                        Showing {filteredIncidents.length} of {incidents.length}
                                    </div>
                                </div>

                                {/* Error banner */}
                                {incidentsError && (
                                    <div style={{ background: 'rgba(192,57,43,0.08)', border: '1px solid rgba(192,57,43,0.3)', borderRadius: 8, padding: '12px 16px', display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                                        <FontAwesomeIcon icon={faCircleXmark} style={{ color: 'var(--critical)', marginTop: 2, flexShrink: 0 }} />
                                        <div>
                                            <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--critical)', marginBottom: 4 }}>Incidents failed to load</div>
                                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'monospace', wordBreak: 'break-word' }}>{incidentsError}</div>
                                        </div>
                                    </div>
                                )}

                                {/* Table */}
                                <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                                    {filteredIncidents.length === 0 ? (
                                        <div className="empty-state" style={{ padding: 60 }}>
                                            <div className="empty-state-text">
                                                {incidentsError ? 'Fix the error above to load incidents' : 'No incidents match the current filters'}
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="data-table-wrap">
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th style={{ width: 70 }}>#</th>
                                                        <th>Title</th>
                                                        <th style={{ width: 90 }}>Severity</th>
                                                        <th style={{ width: 90 }}>Status</th>
                                                        <th style={{ width: 160 }}>Owner</th>
                                                        <th style={{ width: 140 }}>Created</th>
                                                        <th style={{ width: 80 }}>MTTR</th>
                                                        <th style={{ width: 120 }}>Tactics</th>
                                                        <th style={{ width: 120 }}>Classification</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {filteredIncidents.map(inc => (
                                                        <tr key={inc.number} style={{ cursor: 'pointer' }} onClick={() => setSelectedIncident(inc)}>
                                                            <td style={{ fontWeight: 700, color: 'var(--text-muted)', fontSize: 12 }}>{inc.number}</td>
                                                            <td style={{ maxWidth: 260 }}>
                                                                <button
                                                                    onClick={e => { e.stopPropagation(); setSelectedIncident(inc); }}
                                                                    style={{
                                                                        background: 'none', border: 'none', padding: 0,
                                                                        color: 'var(--text-link)', cursor: 'pointer',
                                                                        fontSize: 12, fontWeight: 600, textAlign: 'left',
                                                                        overflow: 'hidden', textOverflow: 'ellipsis',
                                                                        whiteSpace: 'nowrap', maxWidth: 240, display: 'block',
                                                                    }}
                                                                    title={inc.title}
                                                                >
                                                                    {inc.title}
                                                                </button>
                                                                {inc.description && (
                                                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }} title={inc.description}>
                                                                        {inc.description}
                                                                    </div>
                                                                )}
                                                            </td>
                                                            <td>
                                                                <span style={{ fontSize: 11, fontWeight: 700, color: sevColor(inc.severity), background: sevBg(inc.severity), padding: '2px 8px', borderRadius: 10 }}>
                                                                    {inc.severity}
                                                                </span>
                                                            </td>
                                                            <td>
                                                                <span style={{
                                                                    fontSize: 11, fontWeight: 700,
                                                                    color: inc.status === 'Closed' ? 'var(--low)' : 'var(--critical)',
                                                                    background: inc.status === 'Closed' ? 'rgba(39,174,96,0.10)' : 'rgba(192,57,43,0.10)',
                                                                    padding: '2px 8px', borderRadius: 10
                                                                }}>
                                                                    {inc.status}
                                                                </span>
                                                            </td>
                                                            <td style={{ fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160 }} title={inc.owner}>{inc.owner}</td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(inc.created)}</td>
                                                            <td style={{ fontSize: 12, fontWeight: 600, color: inc.mttr_hours > 24 ? 'var(--critical)' : inc.mttr_hours > 8 ? 'var(--high)' : 'var(--low)' }}>
                                                                {formatHours(inc.mttr_hours)}
                                                                {inc.status !== 'Closed' && <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 400 }}> (open)</span>}
                                                            </td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 120 }} title={tacticStr(inc.tactics) || '—'}>
                                                                {tacticStr(inc.tactics) || '—'}
                                                            </td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{inc.classification || '—'}</td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}
                                </div>

                                {/* Recurrence panel */}
                                {recurrence.length > 0 && (
                                    <div className="card" style={{ padding: 0 }}>
                                        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
                                            <FontAwesomeIcon icon={faRepeat} style={{ color: 'var(--high)', fontSize: 13 }} />
                                            <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-primary)' }}>Recurring Incident Patterns</span>
                                            <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 4 }}>{recurrence.length} repeat titles detected — possible detection rule noise</span>
                                        </div>
                                        <div className="data-table-wrap">
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th>Title</th>
                                                        <th style={{ width: 70 }}>Count</th>
                                                        <th style={{ width: 80 }}>Open</th>
                                                        <th style={{ width: 120 }}>First Seen</th>
                                                        <th style={{ width: 120 }}>Last Seen</th>
                                                        <th style={{ width: 100 }}>Avg MTTR</th>
                                                        <th style={{ width: 140 }}>Severities</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {recurrence.map((r, i) => (
                                                        <tr key={i}>
                                                            <td style={{ fontWeight: 600, fontSize: 12, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.title}>{r.title}</td>
                                                            <td style={{ fontWeight: 800, color: 'var(--high)', fontSize: 14 }}>{r.count}</td>
                                                            <td style={{ color: r.open_count > 0 ? 'var(--critical)' : 'var(--text-muted)', fontWeight: 600 }}>{r.open_count}</td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.first_seen)}</td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.last_seen)}</td>
                                                            <td style={{ fontSize: 12 }}>{r.avg_mttr >= 0 ? formatHours(r.avg_mttr) : '—'}</td>
                                                            <td style={{ fontSize: 11 }}>
                                                                {(Array.isArray(r.severities) ? r.severities : []).map((s, j) => (
                                                                    <span key={j} style={{ marginRight: 4, color: sevColor(s), fontWeight: 700 }}>{s}</span>
                                                                ))}
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* ── AI Assessment ── */}
                        {tab === 'ai' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                {/* Context card */}
                                <div className="card" style={{ background: 'linear-gradient(135deg, rgba(208,74,2,0.04) 0%, rgba(208,74,2,0.01) 100%)', border: '1px solid rgba(208,74,2,0.15)' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                                        <FontAwesomeIcon icon={faRobot} style={{ color: 'var(--brand)', fontSize: 18 }} />
                                        <div>
                                            <div style={{ fontWeight: 800, fontSize: 14, color: 'var(--text-primary)' }}>AI SOC Assessment</div>
                                            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                                                Claude analyses your full incident dataset and generates prioritised operational recommendations
                                            </div>
                                        </div>
                                    </div>
                                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
                                        {[
                                            { label: 'Total Incidents',   value: summary?.total ?? 0,          color: 'var(--brand)'    },
                                            { label: 'Open',              value: summary?.open ?? 0,           color: 'var(--critical)' },
                                            { label: 'Avg MTTR',          value: formatHours(mttr?.avg_hours ?? 0), color: 'var(--info)'  },
                                            { label: 'Recurring Titles',  value: recurrence.length,            color: 'var(--high)'     },
                                        ].map(item => (
                                            <div key={item.label} style={{ background: 'var(--bg-card)', borderRadius: 8, padding: '10px 14px', border: '1px solid var(--border)' }}>
                                                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{item.label}</div>
                                                <div style={{ fontSize: 20, fontWeight: 800, color: item.color }}>{item.value}</div>
                                            </div>
                                        ))}
                                    </div>
                                    <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                                        <button className="btn btn-primary" onClick={runAiAssessment} disabled={aiLoading}
                                            style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                            <FontAwesomeIcon icon={aiLoading ? faRefresh : faWandMagicSparkles} spin={aiLoading} />
                                            {aiLoading ? 'Analysing…' : assessment ? 'Regenerate Assessment' : 'Run AI Assessment'}
                                        </button>
                                        {assessment && !aiLoading && (
                                            <span style={{ fontSize: 12, color: 'var(--low)', display: 'flex', alignItems: 'center', gap: 6 }}>
                                                <FontAwesomeIcon icon={faCircleCheck} />
                                                Assessment complete
                                            </span>
                                        )}
                                        <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                                            Context: {days}d window · {incidents.length} incidents · {recurrence.length} recurring · {sla.length} SLA tiers
                                        </span>
                                    </div>
                                </div>

                                <ReportLogPanel
                                    steps={AI_LOG_STEPS}
                                    loading={aiLoading}
                                    success={aiSuccess}
                                    error={aiError}
                                    successMsg="AI assessment generated successfully"
                                />

                                {assessment && !aiLoading && (
                                    <div className="card">
                                        <div style={{ fontSize: 13, lineHeight: 1.7, color: 'var(--text-secondary)' }}
                                            dangerouslySetInnerHTML={{ __html: renderMd(assessment) }} />
                                    </div>
                                )}
                            </div>
                        )}

                    </div>
                )}
            </div>
        </div>

        {selectedIncident && (
            <IncidentDetailModal
                incident={selectedIncident}
                onClose={() => setSelectedIncident(null)}
            />
        )}
        </>
    );
}
