import { useState, useEffect, useMemo } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import {
    faListCheck, faChartBar, faShieldHalved, faTriangleExclamation,
    faSearch, faBellSlash, faFilePdf, faFileCode, faRefresh,
    faXmark, faRobot, faSpinner, faCode, faChevronRight,
    faCopy, faCheck, faCommentDots, faWandMagicSparkles,
    faChevronDown, faChevronUp, faBolt, faCircleXmark,
} from '@fortawesome/free-solid-svg-icons';
import { ReportLogPanel, type LogStep } from '../components/ReportLogPanel';

// ── Types ─────────────────────────────────────────────────────────────────────
interface Overview { total_alerts: number; unique_rules: number; high_alerts: number; medium_alerts: number; low_alerts: number; }
interface Rule { name: string; product: string; severity: string; alert_count: number; last_fired: string; first_fired: string; linked_incidents: number; }
interface TacticRow { tactic: string; alert_count: number; unique_rules: number; }
interface TrendPoint { date: string; High: number; Medium: number; Low: number; Informational: number; }
interface SilentRule { name: string; product: string; severity: string; last_fired: string; total_alerts: number; }

interface RuleDefinition {
    display_name?: string; description?: string; severity?: string;
    enabled?: boolean; tactics?: string[]; techniques?: string[];
    query?: string; query_period?: string; query_frequency?: string;
    trigger_threshold?: number; trigger_operator?: string;
    suppression_enabled?: boolean; suppression_duration?: string;
}
interface AlertSample { time: string; severity: string; description: string; tactics: string; entities?: Array<{ type: string; name: string }>; }
interface IncidentComment { incident_number: string | number; incident_title: string; severity: string; status: string; comment: string; }
interface RuleDetail {
    rule_name: string;
    definition: RuleDefinition;
    alert_samples: AlertSample[];
    incident_comments: IncidentComment[];
}
interface TuneSuggestion { suggestion: string; based_on: 'incident_comments' | 'general'; }

// ── Helpers ───────────────────────────────────────────────────────────────────
function sevColor(s: string) {
    if (s === 'High') return 'var(--critical)';
    if (s === 'Medium') return 'var(--high)';
    if (s === 'Low') return 'var(--low)';
    return 'var(--info)';
}
function sevBadge(s: string) {
    if (s === 'High') return 'badge-critical';
    if (s === 'Medium') return 'badge-high';
    if (s === 'Low') return 'badge-low';
    return 'badge-muted';
}
function ruleFreshness(lastFired: string | null): 'green' | 'yellow' | 'red' {
    if (!lastFired) return 'red';
    const hrs = (Date.now() - new Date(lastFired).getTime()) / 3600000;
    if (hrs < 24) return 'green';
    if (hrs < 168) return 'yellow';
    return 'red';
}

function isoToHuman(iso: string): string {
    if (!iso) return '—';
    const h = iso.match(/(\d+)H/)?.[1];
    const m = iso.match(/(\d+)M/)?.[1];
    const d = iso.match(/(\d+)D/)?.[1];
    const parts = [d && `${d}d`, h && `${h}h`, m && `${m}m`].filter(Boolean);
    return parts.length ? parts.join(' ') : iso;
}

// ── Markdown renderer (supports tables, ####, staticColors for HTML export) ───
function renderMd(md: string, staticColors = false): string {
    const clr = {
        brand:   staticColors ? '#D04A02' : 'var(--brand)',
        surface: staticColors ? '#f1f5f9' : 'var(--bg-surface)',
        text:    staticColors ? '#1e293b' : 'var(--text-primary)',
        muted:   staticColors ? '#64748b' : 'var(--text-muted)',
        border:  staticColors ? '#e2e8f0' : 'var(--border)',
        rowAlt:  staticColors ? '#f8fafc' : 'var(--bg-surface)',
    };
    const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const inline = (s: string) => esc(s)
        .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/`(.+?)`/g, `<code style="background:${clr.surface};padding:1px 5px;border-radius:3px;font-size:11px;font-family:monospace;color:${clr.brand}">$1</code>`);

    const lines = md.split('\n');
    const out: string[] = [];
    let i = 0;
    while (i < lines.length) {
        const line = lines[i].trimEnd();
        if (line.startsWith('```')) {
            i++;
            const block: string[] = [];
            while (i < lines.length && !lines[i].startsWith('```')) { block.push(esc(lines[i])); i++; }
            out.push(`<pre style="background:${clr.surface};border:1px solid ${clr.border};border-radius:6px;padding:12px 14px;font-family:monospace;font-size:11.5px;overflow-x:auto;margin:8px 0;line-height:1.6;white-space:pre-wrap;word-break:break-all">${block.join('\n')}</pre>`);
            i++; continue;
        }
        if (/^## /.test(line)) {
            out.push(`<h3 style="color:${clr.brand};margin:20px 0 8px;font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;border-bottom:2px solid ${clr.brand};padding-bottom:5px">${inline(line.slice(3))}</h3>`);
            i++; continue;
        }
        if (/^### /.test(line)) {
            out.push(`<h4 style="margin:14px 0 5px;font-size:12px;font-weight:700;color:${clr.text}">${inline(line.slice(4))}</h4>`);
            i++; continue;
        }
        if (/^#### /.test(line)) {
            out.push(`<h5 style="margin:10px 0 4px;font-size:11.5px;font-weight:600;color:${clr.muted}">${inline(line.slice(5))}</h5>`);
            i++; continue;
        }
        if (/^\|/.test(line)) {
            const tableLines: string[] = [];
            while (i < lines.length && /^\|/.test(lines[i].trimEnd())) {
                tableLines.push(lines[i]);
                i++;
            }
            if (tableLines.length >= 2) {
                const headerCells = tableLines[0].split('|').slice(1, -1).map(cell => cell.trim());
                const dataRows    = tableLines.slice(2);
                let tbl = `<div style="overflow-x:auto;margin:10px 0"><table style="border-collapse:collapse;width:100%;font-size:12px"><thead><tr>`;
                tbl += headerCells.map(cell =>
                    `<th style="padding:7px 10px;border:1px solid ${clr.border};background:${clr.surface};font-weight:700;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.04em;color:${clr.muted}">${inline(cell)}</th>`
                ).join('');
                tbl += '</tr></thead><tbody>';
                dataRows.forEach((row, idx) => {
                    const cells    = row.split('|').slice(1, -1).map(cell => cell.trim());
                    const rowStyle = idx % 2 === 1 ? `background:${clr.rowAlt}` : '';
                    tbl += `<tr style="${rowStyle}">` +
                        cells.map(cell => `<td style="padding:7px 10px;border:1px solid ${clr.border};vertical-align:top;font-size:12px">${inline(cell)}</td>`).join('') +
                        '</tr>';
                });
                tbl += '</tbody></table></div>';
                out.push(tbl);
            }
            continue;
        }
        if (/^[-*] /.test(line)) {
            let ul = '<ul style="padding-left:20px;margin:6px 0">';
            while (i < lines.length && /^[-*] /.test(lines[i])) {
                ul += `<li style="margin:3px 0;font-size:12.5px;line-height:1.6">${inline(lines[i].replace(/^[-*] /, ''))}</li>`; i++;
            }
            out.push(ul + '</ul>'); continue;
        }
        if (/^\d+\. /.test(line)) {
            let ol = '<ol style="padding-left:20px;margin:6px 0">';
            while (i < lines.length && /^\d+\. /.test(lines[i])) {
                ol += `<li style="margin:3px 0;font-size:12.5px;line-height:1.6">${inline(lines[i].replace(/^\d+\. /, ''))}</li>`; i++;
            }
            out.push(ol + '</ol>'); continue;
        }
        if (line.trim() === '') { out.push('<div style="height:5px"></div>'); i++; continue; }
        out.push(`<p style="margin:4px 0;font-size:12.5px;line-height:1.7">${inline(line)}</p>`); i++;
    }
    return out.join('\n');
}

// ── HTML export builder for the AI report ─────────────────────────────────────
function buildAnalyticsReportHtml(content: string, days: number, generatedAt: string): string {
    const body = renderMd(content, true);
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Analytics Rules Assessment Report</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:0;margin:0;color:#1e293b;background:#f8fafc}
  .page{max-width:960px;margin:0 auto;padding:48px 40px}
  .report-header{background:linear-gradient(135deg,#D04A02 0%,#b83d01 100%);color:#fff;padding:32px 40px;margin:-48px -40px 36px}
  .report-header h1{font-size:24px;font-weight:800;margin:0 0 6px;color:#fff}
  .report-header .meta{font-size:12px;opacity:.85;margin:0}
  .confidential{display:inline-block;margin-top:10px;padding:3px 10px;background:rgba(255,255,255,.2);border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
  h3{color:#D04A02;margin:28px 0 10px;font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;border-bottom:2px solid #D04A02;padding-bottom:6px}
  h4{margin:18px 0 6px;font-size:13px;font-weight:700;color:#1e293b}
  h5{margin:12px 0 4px;font-size:12px;font-weight:600;color:#64748b}
  p{margin:5px 0;font-size:13px;line-height:1.7;color:#334155}
  ul,ol{padding-left:22px;margin:8px 0}
  li{margin:4px 0;font-size:13px;line-height:1.6}
  table{border-collapse:collapse;width:100%;font-size:12px;margin:12px 0}
  th{padding:7px 12px;border:1px solid #e2e8f0;background:#f1f5f9;font-weight:700;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#475569}
  td{padding:7px 12px;border:1px solid #e2e8f0;vertical-align:top;color:#334155}
  tr:nth-child(even) td{background:#f8fafc}
  code{background:#f1f5f9;padding:1px 6px;border-radius:3px;font-size:11px;font-family:monospace;color:#0f172a}
  pre{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:12px 16px;font-size:12px;overflow-x:auto;margin:10px 0;white-space:pre-wrap;word-break:break-all}
  strong{font-weight:700}em{font-style:italic}
  div[style*="overflow-x:auto"]{overflow-x:auto}
  .footer{margin-top:40px;padding-top:16px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;font-size:11px;color:#94a3b8}
  @media print{.report-header{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>
</head>
<body>
<div class="page">
  <div class="report-header">
    <h1>Analytics Rules Assessment Report</h1>
    <p class="meta">Period: Last ${days} days &nbsp;·&nbsp; Generated: ${new Date(generatedAt).toLocaleString()}</p>
    <span class="confidential">Confidential — Internal Use Only</span>
  </div>
  <div class="report-body">${body}</div>
  <div class="footer">
    <span>Sentinel Vigil · Microsoft Sentinel</span>
    <span>Analytics Rules Assessment · ${new Date(generatedAt).toLocaleString()}</span>
  </div>
</div>
</body>
</html>`;
}

// ── Rule Detail Panel ─────────────────────────────────────────────────────────
interface PanelProps { rule: Rule; days: number; onClose: () => void; }

function RuleDetailPanel({ rule, days, onClose }: PanelProps) {
    const [detail, setDetail]           = useState<RuleDetail | null>(null);
    const [detailLoading, setDetailLoading] = useState(true);
    const [detailTab, setDetailTab]     = useState<'properties' | 'tune'>('properties');
    const [suggestion, setSuggestion]   = useState<TuneSuggestion | null>(null);
    const [tuning, setTuning]           = useState(false);
    const [tuneSuccess, setTuneSuccess] = useState<boolean | null>(null);
    const [tuneError, setTuneError]     = useState<string | null>(null);
    const [copied, setCopied]           = useState(false);

    useEffect(() => {
        setDetail(null); setSuggestion(null); setTuneError(null); setTuneSuccess(null);
        setDetailTab('properties'); setDetailLoading(true);
        axios.get(`/api/analytics-rules/rule-detail?name=${encodeURIComponent(rule.name)}&days=${days}`, { timeout: 0 })
            .then(r => setDetail(r.data))
            .catch(e => console.error('Rule detail fetch failed:', e))
            .finally(() => setDetailLoading(false));
    }, [rule.name, days]);

    const getTuneSuggestion = async () => {
        setTuning(true); setTuneError(null); setTuneSuccess(null); setSuggestion(null);
        try {
            const res = await axios.post('/api/analytics-rules/tune-suggestion', {
                rule_name:         rule.name,
                kql_query:         detail?.definition?.query ?? '',
                incident_comments: detail?.incident_comments ?? [],
                alert_count:       rule.alert_count,
                severity:          rule.severity,
                description:       detail?.definition?.description ?? '',
            }, { timeout: 0 });
            setSuggestion(res.data);
            setTuneSuccess(true);
            setDetailTab('tune');
        } catch (e: any) {
            setTuneError(e.response?.data?.detail || e.message || 'Suggestion failed');
            setTuneSuccess(false);
        } finally { setTuning(false); }
    };

    const copyKql = () => {
        const q = detail?.definition?.query;
        if (!q) return;
        navigator.clipboard.writeText(q).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        });
    };

    const def = detail?.definition ?? {};
    const hasKql = !!def.query;
    const commentCount = detail?.incident_comments?.length ?? 0;

    const tuneLogSteps: LogStep[] = commentCount > 0 ? [
        { level: 'info', msg: 'Loading rule definition and KQL query…',     delay: 400  },
        { level: 'info', msg: `Reviewing ${commentCount} incident comment${commentCount !== 1 ? 's' : ''}…`, delay: 2000 },
        { level: 'info', msg: 'Identifying false positive patterns…',        delay: 4500 },
        { level: 'ai',   msg: 'Running LLM analysis with Claude…',           delay: 7000 },
        { level: 'ai',   msg: 'Generating evidence-based recommendations…',  delay: 11000 },
    ] : [
        { level: 'info', msg: 'Loading rule definition and KQL query…',     delay: 400  },
        { level: 'info', msg: 'Analysing detection logic and coverage…',     delay: 2500 },
        { level: 'info', msg: 'Checking for noise and over-broad patterns…', delay: 5000 },
        { level: 'ai',   msg: 'Running LLM analysis with Claude…',           delay: 7500 },
        { level: 'ai',   msg: 'Generating KQL optimisation recommendations…',delay: 11000 },
    ];

    return (
        <div style={{
            border: '1.5px solid var(--border-color)', borderRadius: 12,
            background: 'var(--bg-card)', overflow: 'hidden',
            display: 'flex', flexDirection: 'column',
            position: 'sticky', top: 16, maxHeight: 'calc(100vh - 120px)',
        }}>
            {/* ── Panel header ── */}
            <div style={{
                padding: '14px 16px 12px',
                background: 'var(--bg-higher)',
                borderBottom: '1px solid var(--border-color)',
            }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.4, wordBreak: 'break-word' }}>
                            {rule.name}
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 6, flexWrap: 'wrap' }}>
                            <span className={`badge ${sevBadge(rule.severity)}`}>{rule.severity}</span>
                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                {rule.alert_count.toLocaleString()} alerts
                            </span>
                            {rule.linked_incidents > 0 && (
                                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                    · {rule.linked_incidents} incidents
                                </span>
                            )}
                            {commentCount > 0 && (
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, fontWeight: 700, color: 'var(--brand)', background: 'var(--pwc-orange-light)', padding: '1px 7px', borderRadius: 10 }}>
                                    <FontAwesomeIcon icon={faCommentDots} style={{ fontSize: 9 }} />
                                    {commentCount} comment{commentCount !== 1 ? 's' : ''}
                                </span>
                            )}
                        </div>
                    </div>
                    <button onClick={onClose} className="btn btn-sm btn-ghost" style={{ flexShrink: 0, padding: '4px 7px' }}>
                        <FontAwesomeIcon icon={faXmark} />
                    </button>
                </div>

                {/* Tabs */}
                <div className="tabs" style={{ marginTop: 12, marginBottom: 0, gap: 4 }}>
                    {(['properties', 'tune'] as const).map(t => (
                        <button key={t} onClick={() => setDetailTab(t)}
                            className={`tab ${detailTab === t ? 'active' : ''}`}
                            style={{ borderRadius: 6 }}>
                            {t === 'properties' ? (
                                <><FontAwesomeIcon icon={faCode} style={{ marginRight: 5 }} />Properties</>
                            ) : (
                                <><FontAwesomeIcon icon={faWandMagicSparkles} style={{ marginRight: 5 }} />AI Tune</>
                            )}
                        </button>
                    ))}
                </div>
            </div>

            {/* ── Panel body ── */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px' }}>
                {detailLoading ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-muted)', padding: '20px 0' }}>
                        <FontAwesomeIcon icon={faSpinner} spin style={{ color: 'var(--brand)' }} />
                        <span style={{ fontSize: 12 }}>Loading rule details…</span>
                    </div>
                ) : detailTab === 'properties' ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

                        {/* Firing stats */}
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                            {[
                                { label: 'First Fired', val: rule.first_fired ? new Date(rule.first_fired).toLocaleDateString() : '—' },
                                { label: 'Last Fired',  val: rule.last_fired  ? new Date(rule.last_fired).toLocaleDateString()  : '—' },
                            ].map(s => (
                                <div key={s.label} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 7, padding: '8px 10px' }}>
                                    <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>{s.label}</div>
                                    <div style={{ fontSize: 12, fontWeight: 700 }}>{s.val}</div>
                                </div>
                            ))}
                        </div>

                        {/* Rule definition (from Sentinel API) */}
                        {def.description && (
                            <div>
                                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 5 }}>Description</div>
                                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{def.description}</div>
                            </div>
                        )}

                        {(def.tactics?.length || def.techniques?.length) ? (
                            <div>
                                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 5 }}>MITRE ATT&amp;CK</div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                                    {def.tactics?.map(t => (
                                        <span key={t} style={{ fontSize: 10, fontWeight: 700, background: 'rgba(208,74,2,0.1)', color: 'var(--brand)', padding: '2px 8px', borderRadius: 10 }}>{t}</span>
                                    ))}
                                    {def.techniques?.map(t => (
                                        <code key={t} style={{ fontSize: 10, background: 'var(--bg-surface)', color: 'var(--text-muted)', padding: '2px 6px', borderRadius: 4 }}>{t}</code>
                                    ))}
                                </div>
                            </div>
                        ) : null}

                        {(def.query_frequency || def.query_period || def.trigger_threshold !== undefined) && (
                            <div>
                                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 5 }}>Rule Configuration</div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                                    {[
                                        { label: 'Run frequency',  val: isoToHuman(def.query_frequency ?? '') },
                                        { label: 'Lookup period',  val: isoToHuman(def.query_period ?? '') },
                                        { label: 'Trigger',        val: def.trigger_operator ? `${def.trigger_operator} ${def.trigger_threshold ?? 0}` : '—' },
                                        { label: 'Suppression',    val: def.suppression_enabled ? isoToHuman(def.suppression_duration ?? '') : 'Off' },
                                    ].filter(r => r.val && r.val !== '—').map(r => (
                                        <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, padding: '3px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                                            <span style={{ color: 'var(--text-muted)' }}>{r.label}</span>
                                            <span style={{ fontWeight: 600 }}>{r.val}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* KQL Query */}
                        <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>KQL Query</div>
                                {hasKql && (
                                    <button onClick={copyKql} className="btn btn-sm btn-ghost" style={{ fontSize: 10, padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 4 }}>
                                        <FontAwesomeIcon icon={copied ? faCheck : faCopy} style={{ color: copied ? 'var(--low)' : undefined }} />
                                        {copied ? 'Copied' : 'Copy'}
                                    </button>
                                )}
                            </div>
                            {hasKql ? (
                                <pre style={{
                                    background: 'var(--bg-surface)', border: '1px solid var(--border)',
                                    borderRadius: 7, padding: '10px 12px', fontSize: 11,
                                    fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'pre-wrap',
                                    wordBreak: 'break-all', color: 'var(--text-primary)', lineHeight: 1.65,
                                    maxHeight: 280, overflowY: 'auto', margin: 0,
                                }}>
                                    {def.query}
                                </pre>
                            ) : (
                                <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic', padding: '8px 0' }}>
                                    KQL not available — this may be a built-in or Microsoft-managed rule. Configure Resource Group and Workspace Name in Settings to enable rule definition fetching.
                                </div>
                            )}
                        </div>

                        {/* Alert samples */}
                        {detail?.alert_samples && detail.alert_samples.length > 0 && (
                            <div>
                                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
                                    Recent Alerts ({detail.alert_samples.length})
                                </div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                                    {detail.alert_samples.map((s, i) => (
                                        <div key={i} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 7, padding: '8px 10px' }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                                                <span className={`badge ${sevBadge(s.severity)}`} style={{ fontSize: 9 }}>{s.severity}</span>
                                                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{s.time ? new Date(s.time).toLocaleString() : '—'}</span>
                                            </div>
                                            {s.description && <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{s.description.slice(0, 180)}{s.description.length > 180 ? '…' : ''}</div>}
                                            {s.tactics && <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>{s.tactics}</div>}
                                            {s.entities && s.entities.length > 0 && (
                                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                                                    {s.entities.map((e, ei) => (
                                                        <span key={ei} style={{
                                                            fontSize: 10, padding: '1px 7px', borderRadius: 10,
                                                            background: 'var(--bg-higher)', border: '1px solid var(--border-color)',
                                                            color: 'var(--text-secondary)', display: 'inline-flex', alignItems: 'center', gap: 3,
                                                        }}>
                                                            <span style={{ color: 'var(--brand)', fontWeight: 700, fontSize: 9, textTransform: 'uppercase' }}>{e.type}</span>
                                                            <span>{e.name}</span>
                                                        </span>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Incident comments */}
                        {commentCount > 0 && (
                            <div>
                                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
                                    Incident Comments ({commentCount})
                                </div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                                    {detail!.incident_comments.map((c, i) => (
                                        <div key={i} style={{ background: 'rgba(208,74,2,0.04)', border: '1px solid rgba(208,74,2,0.18)', borderRadius: 7, padding: '8px 10px' }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4, flexWrap: 'wrap', gap: 4 }}>
                                                <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--brand)' }}>#{c.incident_number}</span>
                                                <div style={{ display: 'flex', gap: 5 }}>
                                                    <span className={`badge ${sevBadge(c.severity)}`} style={{ fontSize: 9 }}>{c.severity}</span>
                                                    <span style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>{c.status}</span>
                                                </div>
                                            </div>
                                            <div
                                                style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.55 }}
                                                dangerouslySetInnerHTML={{ __html: renderMd(c.comment) }}
                                            />
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {!detailLoading && !def.query && detail?.alert_samples?.length === 0 && commentCount === 0 && (
                            <div style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', padding: '16px 0' }}>
                                No additional detail available for this rule in the selected period.
                            </div>
                        )}
                    </div>
                ) : (
                    /* ── AI Tune tab ── */
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                        {/* Context badge */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Suggestion basis:</span>
                            {commentCount > 0 ? (
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700, color: 'var(--brand)', background: 'rgba(208,74,2,0.08)', padding: '3px 10px', borderRadius: 10 }}>
                                    <FontAwesomeIcon icon={faCommentDots} style={{ fontSize: 10 }} />
                                    {commentCount} incident comment{commentCount !== 1 ? 's' : ''}
                                </span>
                            ) : (
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', background: 'var(--bg-surface)', padding: '3px 10px', borderRadius: 10, border: '1px solid var(--border)' }}>
                                    <FontAwesomeIcon icon={faCode} style={{ fontSize: 10 }} />
                                    General KQL analysis
                                </span>
                            )}
                        </div>

                        {commentCount === 0 && (
                            <div style={{ fontSize: 12, color: 'var(--text-muted)', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '8px 12px', lineHeight: 1.6 }}>
                                No incident comments found for this rule. Suggestions will be based on a general KQL quality and best-practice analysis.
                            </div>
                        )}

                        {!suggestion && (
                            <button
                                className="btn btn-primary"
                                onClick={getTuneSuggestion}
                                disabled={tuning}
                                style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' }}
                            >
                                <FontAwesomeIcon icon={tuning ? faSpinner : faWandMagicSparkles} spin={tuning} />
                                {tuning ? 'Analysing with Claude…' : 'Get Fine-Tuning Suggestions'}
                            </button>
                        )}

                        <ReportLogPanel
                            steps={tuneLogSteps}
                            loading={tuning}
                            success={tuneSuccess}
                            error={tuneError}
                            successMsg="Fine-tuning suggestions generated"
                        />

                        {suggestion && (
                            <div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontWeight: 700, color: suggestion.based_on === 'incident_comments' ? 'var(--brand)' : 'var(--text-muted)', background: suggestion.based_on === 'incident_comments' ? 'rgba(208,74,2,0.08)' : 'var(--bg-surface)', padding: '3px 9px', borderRadius: 10, border: '1px solid var(--border)' }}>
                                        <FontAwesomeIcon icon={suggestion.based_on === 'incident_comments' ? faCommentDots : faCode} style={{ fontSize: 9 }} />
                                        Based on {suggestion.based_on === 'incident_comments' ? 'incident comments' : 'general KQL analysis'}
                                    </span>
                                    <button className="btn btn-sm btn-ghost" onClick={getTuneSuggestion} disabled={tuning} style={{ fontSize: 11 }}>
                                        <FontAwesomeIcon icon={faRefresh} spin={tuning} style={{ marginRight: 4 }} />Refresh
                                    </button>
                                </div>
                                <div
                                    style={{ lineHeight: 1.7 }}
                                    dangerouslySetInnerHTML={{ __html: renderMd(suggestion.suggestion) }}
                                />
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}

// ── AI Bulk Report Panel ──────────────────────────────────────────────────────
interface TokenUsage { input_tokens: number; output_tokens: number; model: string; }

const REPORT_LOG_STEPS = [
    { level: 'info' as const, msg: 'Connecting to Sentinel workspace…',                      delay: 400  },
    { level: 'info' as const, msg: 'Loading active rule inventory and alert volumes…',       delay: 2500 },
    { level: 'info' as const, msg: 'Fetching MITRE ATT&CK tactic distribution…',            delay: 5000 },
    { level: 'info' as const, msg: 'Pulling rule definitions and KQL queries…',             delay: 8000 },
    { level: 'info' as const, msg: 'Analysing alert trends and silent rule coverage…',      delay: 11500 },
    { level: 'ai'   as const, msg: 'Running LLM analysis with Claude…',                     delay: 14500 },
    { level: 'ai'   as const, msg: 'Generating rule recommendations and MITRE scorecard…',  delay: 22000 },
    { level: 'ai'   as const, msg: 'Finalising prioritised action plan…',                   delay: 30000 },
];

function AiReportPanel({ days }: { days: number }) {
    const [loading,  setLoading]  = useState(false);
    const [success,  setSuccess]  = useState<boolean | null>(null);
    const [report,   setReport]   = useState<{ llm_analysis: string; generated_at: string; token_usage?: TokenUsage } | null>(null);
    const [error,    setError]    = useState<string | null>(null);
    const [expanded, setExpanded] = useState(true);
    const [model,    setModel]    = useState('claude-sonnet-4-6');

    const generate = async () => {
        setLoading(true); setError(null); setReport(null); setSuccess(null);
        try {
            const res = await axios.get(`/api/analytics-rules/report?days=${days}&model=${model}`, { timeout: 0 });
            setReport(res.data);
            setExpanded(true);
            setSuccess(true);
        } catch (e: any) {
            setError(e.response?.data?.detail || e.message || 'Report generation failed');
            setSuccess(false);
        } finally { setLoading(false); }
    };

    const doExport = async (format: 'html' | 'pdf') => {
        if (!report) return;
        const html = buildAnalyticsReportHtml(report.llm_analysis, days, report.generated_at);
        try {
            const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const res = await axios.post(endpoint,
                { html, filename: `Analytics_Rules_Report_${days}d.${format}` },
                { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url;
            a.download = `Analytics_Rules_Report_${days}d.${format}`; a.click(); a.remove();
        } catch (e: any) { setError(`Export failed: ${e.message}`); }
    };

    return (
        <div className="card" style={{ border: '1.5px solid var(--brand)', marginBottom: 0 }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: report ? 12 : 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <FontAwesomeIcon icon={faRobot} style={{ color: 'var(--brand)', fontSize: 18 }} />
                    <div>
                        <div style={{ fontWeight: 700, fontSize: 14 }}>AI Analytics Rules Assessment Report</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            LLM-powered analysis across all detection rules, MITRE coverage, and alert volumes — last {days} days
                        </div>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    {report && (
                        <>
                            <button className="btn btn-secondary btn-sm" onClick={() => doExport('html')}>
                                <FontAwesomeIcon icon={faFileCode} style={{ color: 'var(--info)' }} /> HTML
                            </button>
                            <button className="btn btn-primary btn-sm" onClick={() => doExport('pdf')}>
                                <FontAwesomeIcon icon={faFilePdf} /> PDF
                            </button>
                            <button className="btn btn-sm btn-ghost" onClick={() => setExpanded(v => !v)}>
                                <FontAwesomeIcon icon={expanded ? faChevronUp : faChevronDown} />
                            </button>
                        </>
                    )}
                    <select
                        value={model}
                        onChange={e => setModel(e.target.value)}
                        disabled={loading}
                        style={{ fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', cursor: 'pointer' }}
                    >
                        <option value="claude-sonnet-4-6">Sonnet 4.6</option>
                        <option value="claude-haiku-4-5">Haiku 4.5</option>

                    </select>
                    <button className="btn btn-sm btn-primary" onClick={generate} disabled={loading}>
                        <FontAwesomeIcon icon={faRobot} spin={loading} style={{ marginRight: 6 }} />
                        {loading ? 'Generating…' : report ? 'Regenerate' : 'Generate Report'}
                    </button>
                </div>
            </div>

            <ReportLogPanel
                steps={REPORT_LOG_STEPS}
                loading={loading}
                success={success}
                error={error}
                successMsg="Analytics rules report generated"
            />

            {error && !loading && (
                <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(192,57,43,0.07)', border: '1px solid rgba(192,57,43,0.25)', borderRadius: 8, fontSize: 12, color: 'var(--critical)' }}>
                    <FontAwesomeIcon icon={faCircleXmark} style={{ marginRight: 8 }} />{error}
                </div>
            )}

            {report && expanded && (
                <div style={{ marginTop: 16, borderTop: '1px solid var(--border)', paddingTop: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 14, flexWrap: 'wrap' }}>
                        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                            Generated {new Date(report.generated_at).toLocaleString()}
                        </span>
                        {report.token_usage && (
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'monospace', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '2px 8px', color: 'var(--text-muted)' }}>
                                <FontAwesomeIcon icon={faBolt} style={{ color: '#f59e0b', fontSize: 9 }} />
                                <span style={{ color: 'var(--info)' }}>{report.token_usage.input_tokens.toLocaleString()}</span>
                                <span>in</span>
                                <span style={{ opacity: 0.5 }}>→</span>
                                <span style={{ color: '#27ae60' }}>{report.token_usage.output_tokens.toLocaleString()}</span>
                                <span>out</span>
                                <span style={{ opacity: 0.4 }}>·</span>
                                <span style={{ opacity: 0.7 }}>{report.token_usage.model}</span>
                            </span>
                        )}
                    </div>
                    <div
                        style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: '20px 24px', lineHeight: 1.7 }}
                        dangerouslySetInnerHTML={{ __html: renderMd(report.llm_analysis) }}
                    />
                </div>
            )}
        </div>
    );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function AnalyticsRules() {
    const [tab, setTab] = useState<'activity' | 'tactic' | 'trend' | 'silent' | 'report'>('activity');
    const [days, setDays] = useState(30);
    const [overview, setOverview] = useState<Overview | null>(null);
    const [rules, setRules] = useState<Rule[]>([]);
    const [tactics, setTactics] = useState<TacticRow[]>([]);
    const [trend, setTrend] = useState<TrendPoint[]>([]);
    const [silentRules, setSilentRules] = useState<SilentRule[]>([]);
    const [loading, setLoading] = useState(true);
    const [isExporting, setIsExporting] = useState(false);
    const [search, setSearch] = useState('');
    const [sevFilter, setSevFilter] = useState('All');
    const [selectedRule, setSelectedRule] = useState<Rule | null>(null);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [ov, act, tac, tr, sr] = await Promise.all([
                axios.get(`/api/analytics-rules/overview?days=${days}`),
                axios.get(`/api/analytics-rules/activity?days=${days}`),
                axios.get(`/api/analytics-rules/by-tactic?days=${days}`),
                axios.get(`/api/analytics-rules/trend?days=${days}`),
                axios.get(`/api/analytics-rules/silent-rules?days=${days}`),
            ]);
            setOverview(ov.data);
            setRules(act.data.rules || []);
            setTactics(tac.data.tactics || []);
            setTrend(tr.data.trend || []);
            setSilentRules(sr.data.silent_rules || []);
        } catch (e) {
            console.error('AnalyticsRules fetch failed', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, [days]);

    // When days change or tab changes away from activity, close the panel
    useEffect(() => { if (tab !== 'activity') setSelectedRule(null); }, [tab]);

    const filteredRules = useMemo(() =>
        rules.filter(r =>
            (sevFilter === 'All' || r.severity === sevFilter) &&
            r.name.toLowerCase().includes(search.toLowerCase())
        ), [rules, search, sevFilter]);

    const maxAlerts = Math.max(...filteredRules.map(r => r.alert_count), 1);
    const maxTacticAlerts = Math.max(...tactics.map(t => t.alert_count), 1);
    const maxTrend = Math.max(...trend.map(t => t.High + t.Medium + t.Low + t.Informational), 1);

    const handleExport = async (format: 'pdf' | 'html') => {
        setIsExporting(true);
        const html = `<div style="font-family:Inter,sans-serif;padding:40px;color:#2D2D2D">
            <h1 style="color:#D04A02;border-bottom:3px solid #D04A02;padding-bottom:16px">Analytics Rules Report</h1>
            <p>Period: Last ${days} days · Generated: ${new Date().toLocaleString()}</p>
            <p><strong>Total Alerts:</strong> ${overview?.total_alerts} · <strong>Active Rules:</strong> ${overview?.unique_rules}</p>
            <h2>Top Firing Rules</h2>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#F7F7F7"><th style="padding:10px;border:1px solid #E5E5E5;text-align:left">Rule</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Severity</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Alerts</th></tr>
                ${rules.slice(0,20).map(r => `<tr>
                    <td style="padding:8px;border:1px solid #E5E5E5">${r.name}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${r.severity}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;font-weight:700">${r.alert_count}</td>
                </tr>`).join('')}
            </table></div>`;
        try {
            const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const res = await axios.post(endpoint, { html, filename: `Analytics_Rules_${days}d.${format}` }, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url; a.download = `Analytics_Rules.${format}`; a.click(); a.remove();
        } catch (e: any) { alert(`Export failed: ${e.message}`); }
        finally { setIsExporting(false); }
    };

    const Skeleton = () => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                {[1,2,3,4].map(i => <div key={i} className="stat-tile"><div className="skeleton skeleton-title" /><div className="skeleton skeleton-text" /></div>)}
            </div>
            <div className="card"><div className="skeleton skeleton-box" style={{ height: 280 }} /></div>
        </div>
    );

    return (
        <div>
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faListCheck} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Analytics Rules
                        </div>
                        <div className="page-subtitle">Detection rule coverage, alert volume, MITRE tactic distribution, and silent rules</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <button className="btn btn-secondary btn-sm" onClick={() => handleExport('html')} disabled={isExporting || loading}>
                            <FontAwesomeIcon icon={faFileCode} style={{ color: 'var(--info)' }} /> HTML
                        </button>
                        <button className="btn btn-primary btn-sm" onClick={() => handleExport('pdf')} disabled={isExporting || loading}>
                            <FontAwesomeIcon icon={faFilePdf} /> PDF
                        </button>
                        <button className="btn btn-sm btn-ghost" onClick={fetchData} disabled={loading}>
                            <FontAwesomeIcon icon={faRefresh} spin={loading} /> Refresh
                        </button>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-card)', padding: '4px 12px', borderRadius: 8, border: '1px solid var(--border-color)' }}>
                            <span style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Period</span>
                            <select value={days} onChange={e => setDays(Number(e.target.value))} disabled={loading}
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
                    </div>
                </div>
            </div>

            <div className="page-content">
                {loading ? <Skeleton /> : (
                    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                        {/* KPIs */}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--brand)' }}>
                                <div className="stat-tile-label">Active Rules</div>
                                <div className="stat-tile-value">{overview?.unique_rules ?? 0}</div>
                                <div className="text-xs text-muted">Fired at least once</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--info)' }}>
                                <div className="stat-tile-label">Total Alerts</div>
                                <div className="stat-tile-value" style={{ color: 'var(--info)' }}>{(overview?.total_alerts ?? 0).toLocaleString()}</div>
                                <div className="text-xs text-muted">Last {days} days</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--critical)' }}>
                                <div className="stat-tile-label">High Severity</div>
                                <div className="stat-tile-value" style={{ color: 'var(--critical)' }}>{(overview?.high_alerts ?? 0).toLocaleString()}</div>
                                <div className="text-xs text-muted">Immediate action required</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: `3px solid ${silentRules.length > 0 ? 'var(--high)' : 'var(--low)'}` }}>
                                <div className="stat-tile-label">Silent Rules</div>
                                <div className="stat-tile-value" style={{ color: silentRules.length > 0 ? 'var(--high)' : 'var(--low)' }}>{silentRules.length}</div>
                                <div className="text-xs text-muted">Not fired in {days}d</div>
                            </div>
                        </div>

                        {/* Tabs */}
                        <div className="tabs" style={{ marginBottom: 0 }}>
                            {([
                                { id: 'activity', label: 'Rule Activity',   icon: faListCheck },
                                { id: 'tactic',   label: 'MITRE Tactics',   icon: faShieldHalved },
                                { id: 'trend',    label: 'Alert Trend',     icon: faChartBar },
                                { id: 'silent',   label: 'Silent Rules',    icon: faBellSlash },
                                { id: 'report',   label: 'AI Report',       icon: faRobot },
                            ] as const).map(t => (
                                <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                                    <FontAwesomeIcon icon={t.icon} style={{ marginRight: 8 }} />{t.label}
                                    {t.id === 'silent' && silentRules.length > 0 && (
                                        <span className="badge badge-high" style={{ marginLeft: 6, padding: '1px 6px', fontSize: 10 }}>{silentRules.length}</span>
                                    )}
                                </button>
                            ))}
                        </div>

                        {/* Rule Activity — split layout when a rule is selected */}
                        {tab === 'activity' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                            {trend && trend.length > 0 && (
                                <div className="card" style={{ marginBottom: 0 }}>
                                    <div className="chart-title">Alert Trend by Severity</div>
                                    <div className="chart-container chart-container-md">
                                        <ResponsiveContainer width="100%" height="100%">
                                            <LineChart data={trend} margin={{ top: 4, right: 16, left: -10, bottom: 0 }}>
                                                <CartesianGrid strokeDasharray="3 3" stroke="#F0F0F0" vertical={false} />
                                                <XAxis dataKey="date" tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                                                       tickFormatter={(d: string) => d.slice(5)} />
                                                <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                                                <Tooltip contentStyle={{ fontFamily: 'Inter', fontSize: 12, borderRadius: 8 }} />
                                                <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} />
                                                <Line type="monotone" dataKey="High"          stroke="#E67E22" strokeWidth={2} dot={false} />
                                                <Line type="monotone" dataKey="Medium"        stroke="#D4AC0D" strokeWidth={2} dot={false} />
                                                <Line type="monotone" dataKey="Low"           stroke="#27AE60" strokeWidth={2} dot={false} />
                                                <Line type="monotone" dataKey="Informational" stroke="#2980B9" strokeWidth={2} dot={false} />
                                            </LineChart>
                                        </ResponsiveContainer>
                                    </div>
                                </div>
                            )}
                            <div style={{ display: 'grid', gridTemplateColumns: selectedRule ? '1fr 400px' : '1fr', gap: 16, alignItems: 'start' }}>
                                {/* Rules table */}
                                <div className="card" style={{ padding: 0 }}>
                                    <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                                        <div style={{ position: 'relative', flex: 1, minWidth: 180 }}>
                                            <FontAwesomeIcon icon={faSearch} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 12 }} />
                                            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search rules…"
                                                className="form-input"
                                                style={{ width: '100%', paddingLeft: 30, paddingRight: 10, boxSizing: 'border-box' }} />
                                        </div>
                                        <div style={{ display: 'flex', gap: 6 }}>
                                            {(['All', 'High', 'Medium', 'Low', 'Informational'] as const).map(s => (
                                                <button key={s} onClick={() => setSevFilter(s)}
                                                    className={`chip ${sevFilter === s ? 'active' : ''}`}>
                                                    {s}
                                                </button>
                                            ))}
                                        </div>
                                        <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 'auto' }}>{filteredRules.length} rules</span>
                                    </div>
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th></th>
                                                    <th>Rule Name</th>
                                                    <th style={{ width: 90 }}>Severity</th>
                                                    <th style={{ width: 90 }}>Alerts</th>
                                                    <th style={{ width: 90 }}>Incidents</th>
                                                    {!selectedRule && <th>Volume</th>}
                                                    <th style={{ width: 130 }}>Last Fired</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {filteredRules.map((r, i) => {
                                                    const isSelected = selectedRule?.name === r.name;
                                                    return (
                                                        <tr key={i}
                                                            onClick={() => setSelectedRule(isSelected ? null : r)}
                                                            style={{
                                                                cursor: 'pointer',
                                                                background: isSelected ? 'rgba(208,74,2,0.06)' : undefined,
                                                                borderLeft: isSelected ? '3px solid var(--brand)' : '3px solid transparent',
                                                            }}
                                                            onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'var(--bg-surface)'; }}
                                                            onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = ''; }}
                                                        >
                                                            <td style={{ padding: '8px 4px 8px 8px', width: 20 }}>
                                                                <FontAwesomeIcon icon={faChevronRight} style={{ fontSize: 9, color: isSelected ? 'var(--brand)' : 'var(--text-muted)', opacity: isSelected ? 1 : 0.4, transform: isSelected ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s' }} />
                                                            </td>
                                                            <td style={{ fontWeight: 600, fontSize: 12 }}>
                                                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                                    <div className={`health-light ${ruleFreshness(r.last_fired)}`} />
                                                                    <span>{r.name}</span>
                                                                </div>
                                                            </td>
                                                            <td><span className={`badge ${sevBadge(r.severity)}`}>{r.severity}</span></td>
                                                            <td style={{ fontWeight: 700, color: sevColor(r.severity) }}>{r.alert_count.toLocaleString()}</td>
                                                            <td style={{ color: 'var(--text-muted)' }}>{r.linked_incidents.toLocaleString()}</td>
                                                            {!selectedRule && (
                                                                <td style={{ width: 160 }}>
                                                                    <div style={{ height: 8, background: '#f0f0f0', borderRadius: 4 }}>
                                                                        <div style={{ width: `${(r.alert_count / maxAlerts) * 100}%`, height: '100%', background: sevColor(r.severity), borderRadius: 4, opacity: 0.85 }} />
                                                                    </div>
                                                                </td>
                                                            )}
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                                {r.last_fired ? new Date(r.last_fired).toLocaleDateString() : '—'}
                                                            </td>
                                                        </tr>
                                                    );
                                                })}
                                                {filteredRules.length === 0 && (
                                                    <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No rules match the filter</td></tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                    {!selectedRule && (
                                        <div style={{ padding: '10px 20px', borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
                                            <FontAwesomeIcon icon={faChevronRight} style={{ fontSize: 9 }} />
                                            Click any rule to view its KQL query, properties, and get AI fine-tuning suggestions
                                        </div>
                                    )}
                                </div>

                                {/* Detail panel */}
                                {selectedRule && (
                                    <RuleDetailPanel
                                        rule={selectedRule}
                                        days={days}
                                        onClose={() => setSelectedRule(null)}
                                    />
                                )}
                            </div>
                            </div>
                        )}

                        {/* MITRE Tactics */}
                        {tab === 'tactic' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                            {tactics && tactics.length > 0 && (
                                <div className="card" style={{ marginBottom: 0 }}>
                                    <div className="chart-title">Alert Volume by MITRE Tactic</div>
                                    <div className="chart-container chart-container-lg">
                                        <ResponsiveContainer width="100%" height="100%">
                                            <BarChart
                                                data={tactics.slice(0, 12).map((t: TacticRow) => ({
                                                    name: (t.tactic || '').slice(0, 20),
                                                    alerts: t.alert_count,
                                                    rules: t.unique_rules,
                                                }))}
                                                layout="vertical"
                                                margin={{ top: 0, right: 20, left: 130, bottom: 0 }}
                                            >
                                                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#F0F0F0" />
                                                <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                                                <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} width={130} />
                                                <Tooltip contentStyle={{ fontFamily: 'Inter', fontSize: 12, borderRadius: 8 }} />
                                                <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} />
                                                <Bar dataKey="alerts" name="Alerts"       fill="#C0392B" radius={[0, 2, 2, 0]} />
                                                <Bar dataKey="rules"  name="Unique Rules" fill="#2980B9" radius={[0, 2, 2, 0]} />
                                            </BarChart>
                                        </ResponsiveContainer>
                                    </div>
                                </div>
                            )}
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20 }}>
                                <div className="card" style={{ padding: 0 }}>
                                    <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
                                        <div className="card-title" style={{ margin: 0 }}>
                                            <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" />
                                            Alerts by MITRE ATT&amp;CK Tactic
                                        </div>
                                    </div>
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead><tr><th>Tactic</th><th style={{ width: 90 }}>Alerts</th><th style={{ width: 90 }}>Rules</th><th>Volume</th></tr></thead>
                                            <tbody>
                                                {tactics.map(t => (
                                                    <tr key={t.tactic}>
                                                        <td style={{ fontWeight: 600, fontSize: 12 }}>{t.tactic}</td>
                                                        <td style={{ fontWeight: 700 }}>{t.alert_count.toLocaleString()}</td>
                                                        <td style={{ color: 'var(--text-muted)' }}>{t.unique_rules}</td>
                                                        <td style={{ width: 180 }}>
                                                            <div style={{ height: 10, background: '#f0f0f0', borderRadius: 5 }}>
                                                                <div style={{ width: `${(t.alert_count / maxTacticAlerts) * 100}%`, height: '100%', background: 'linear-gradient(90deg, var(--brand) 0%, #ff8c42 100%)', borderRadius: 5 }} />
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                                {tactics.length === 0 && <tr><td colSpan={4} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No tactic data — alerts may not have Tactics populated</td></tr>}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faTriangleExclamation} className="card-title-icon" style={{ color: 'var(--high)' }} />
                                        Severity Distribution
                                    </div>
                                    {[
                                        { label: 'High',   count: overview?.high_alerts ?? 0,   color: 'var(--critical)' },
                                        { label: 'Medium', count: overview?.medium_alerts ?? 0, color: 'var(--high)' },
                                        { label: 'Low',    count: overview?.low_alerts ?? 0,    color: 'var(--low)' },
                                    ].map(s => {
                                        const pct = (overview?.total_alerts ?? 0) > 0 ? (s.count / (overview?.total_alerts ?? 1)) * 100 : 0;
                                        return (
                                            <div key={s.label} style={{ marginBottom: 16 }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
                                                    <span style={{ fontWeight: 700, color: s.color, textTransform: 'uppercase' }}>{s.label}</span>
                                                    <span style={{ color: 'var(--text-muted)' }}>{s.count.toLocaleString()} ({pct.toFixed(1)}%)</span>
                                                </div>
                                                <div style={{ height: 12, background: '#f5f5f5', borderRadius: 6 }}>
                                                    <div style={{ width: `${pct}%`, height: '100%', background: s.color, borderRadius: 6, transition: 'width 0.5s ease' }} />
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                            </div>
                        )}

                        {/* Alert Trend */}
                        {tab === 'trend' && (
                            <div className="card">
                                <div className="card-title">
                                    <FontAwesomeIcon icon={faChartBar} className="card-title-icon" />
                                    Daily Alert Trend by Severity
                                </div>
                                <div style={{ display: 'flex', gap: 16, marginBottom: 12, flexWrap: 'wrap' }}>
                                    {[
                                        { label: 'High',          color: 'var(--critical)' },
                                        { label: 'Medium',        color: 'var(--high)' },
                                        { label: 'Low',           color: 'var(--low)' },
                                        { label: 'Informational', color: 'var(--info)' },
                                    ].map(s => (
                                        <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                            <div style={{ width: 10, height: 10, borderRadius: 2, background: s.color }} />{s.label}
                                        </div>
                                    ))}
                                </div>
                                {trend.length === 0 ? (
                                    <div className="empty-state"><div className="empty-state-text">No trend data available</div></div>
                                ) : (
                                    <div>
                                        <div style={{ height: 200, display: 'flex', alignItems: 'flex-end', gap: 3, paddingBottom: 6 }}>
                                            {trend.map((d, i) => {
                                                const total = d.High + d.Medium + d.Low + d.Informational;
                                                const h = (total / maxTrend) * 180;
                                                return (
                                                    <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', height: `${h}px`, minHeight: 2, borderRadius: '3px 3px 0 0', overflow: 'hidden' }}
                                                        title={`${d.date}\nH:${d.High} M:${d.Medium} L:${d.Low}`}>
                                                        <div style={{ flex: d.Informational, background: 'var(--info)',     minHeight: d.Informational > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.Low,           background: 'var(--low)',      minHeight: d.Low > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.Medium,        background: 'var(--high)',     minHeight: d.Medium > 0 ? 1 : 0 }} />
                                                        <div style={{ flex: d.High,          background: 'var(--critical)', minHeight: d.High > 0 ? 1 : 0 }} />
                                                    </div>
                                                );
                                            })}
                                        </div>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                                            <span>{trend[0]?.date}</span>
                                            <span>{trend[trend.length - 1]?.date}</span>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* AI Report */}
                        {tab === 'report' && (
                            <AiReportPanel days={days} />
                        )}

                        {/* Silent Rules */}
                        {tab === 'silent' && (
                            <div>
                                {silentRules.length === 0 ? (
                                    <div className="card">
                                        <div className="empty-state" style={{ padding: 60 }}>
                                            <div className="empty-state-icon"><FontAwesomeIcon icon={faListCheck} style={{ color: 'var(--low)', opacity: 0.6 }} /></div>
                                            <div className="empty-state-text">All rules appear active — no silent detections found</div>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="card" style={{ borderLeft: '3px solid var(--critical)', padding: 0 }}>
                                        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, alignItems: 'center' }}>
                                            <div className="card-title" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                                                <FontAwesomeIcon icon={faBellSlash} className="card-title-icon" style={{ color: 'var(--high)' }} />
                                                Silent Rules
                                                <span className="badge badge-critical">{silentRules.length}</span>
                                            </div>
                                            <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
                                                These rules have fired no alerts in the selected period and may need review.
                                            </div>
                                        </div>
                                        <div className="data-table-wrap">
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th>Rule Name</th>
                                                        <th style={{ width: 100 }}>Severity</th>
                                                        <th style={{ width: 100 }}>Total Alerts</th>
                                                        <th style={{ width: 160 }}>Last Fired</th>
                                                        <th>Days Silent</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {silentRules.map((r, i) => {
                                                        const lastDate = r.last_fired ? new Date(r.last_fired) : null;
                                                        const daysSilent = lastDate ? Math.floor((Date.now() - lastDate.getTime()) / 86400000) : null;
                                                        return (
                                                            <tr key={i}>
                                                                <td style={{ fontWeight: 600, fontSize: 12 }}>{r.name}</td>
                                                                <td><span className={`badge ${sevBadge(r.severity)}`}>{r.severity}</span></td>
                                                                <td>{r.total_alerts.toLocaleString()}</td>
                                                                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{lastDate?.toLocaleDateString() ?? '—'}</td>
                                                                <td>
                                                                    <span className={`badge ${daysSilent && daysSilent > 60 ? 'badge-critical' : 'badge-high'}`}>
                                                                        {daysSilent !== null ? `${daysSilent}d` : '—'}
                                                                    </span>
                                                                </td>
                                                            </tr>
                                                        );
                                                    })}
                                                </tbody>
                                            </table>
                                        </div>
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
