import { useState, useEffect } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faDatabase, faRobot, faCircleCheck, faCircleXmark,
    faTriangleExclamation, faChevronDown, faChevronUp,
    faRefresh, faFilePdf, faFileCode, faBolt,
    faCheckCircle, faExclamationCircle, faInfoCircle,
} from '@fortawesome/free-solid-svg-icons';

// ── Types ─────────────────────────────────────────────────────────────────────
interface Overview {
    dcr_total: number; dcr_succeeded: number; dcr_failed: number;
    dcr_with_transforms: number; dcr_custom_streams: number;
    total_data_flows: number; total_transformations: number;
    ingestion_total_gb: number; ingestion_daily_avg_mb: number;
    ingestion_tables: number; estimated_monthly_gb: number;
    total_errors: number; affected_rules: number;
}
interface DcrRule {
    id: string; name: string; location: string; kind: string;
    provisioning_state: string; created_at: string; last_modified: string;
    days_since_modified: number | null; data_flows: number;
    transformations: number; has_transformation: boolean;
    perf_counters: number; windows_events: number; syslog_sources: number;
    extension_sources: number; log_analytics_count: number;
    workspace_names: string[]; custom_streams: number;
    stream_declarations: string[];
}
interface DcrRulesData {
    rules: DcrRule[]; total: number; succeeded_count: number;
    failed_count: number; with_transformations: number;
    with_custom_streams: number; total_data_flows: number;
    total_transformations: number; error?: string;
}
interface TableRow { table: string; total_mb: number; daily_avg: number; pct: number; }
interface TrendPoint { date: string; total_mb: number; }
interface IngestionData {
    summary: {
        total_mb: number; total_gb: number; table_count: number;
        daily_avg_mb: number; estimated_monthly_gb: number;
    };
    by_table: TableRow[];
    daily_trend: TrendPoint[];
    error?: string;
}
interface DcrError {
    rule_name: string; stream: string; error_code: string;
    message: string; count: number; first_seen: string; last_seen: string;
}
interface DiagEvent { operation: string; result: string; resource: string; count: number; }
interface ErrorsData {
    errors: DcrError[]; diagnostics: DiagEvent[];
    daily_trend: { date: string; rule: string; error_count: number }[];
    total_errors: number; affected_rules: number; error?: string;
}
interface ActivityItem {
    operation: string; resource: string; status: string;
    caller: string; count: number; last_seen: string;
}

type TabId = 'overview' | 'inventory' | 'ingestion' | 'errors' | 'activity' | 'ai';

// ── Markdown renderer (shared with other pages) ───────────────────────────────
function markdownToHtml(md: string, cssVars = true): string {
    const inline = (t: string) => t
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/`(.+?)`/g, cssVars
            ? '<code style="background:var(--bg-surface);padding:1px 5px;border-radius:3px;font-size:11px;font-family:monospace">$1</code>'
            : '<code>$1</code>');

    const h2s = cssVars
        ? 'color:var(--brand);margin:22px 0 10px;font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;border-bottom:2px solid var(--brand);padding-bottom:5px'
        : 'color:#D04A02;margin:22px 0 10px;font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;border-bottom:2px solid #D04A02;padding-bottom:5px';
    const h3s = cssVars ? 'margin:16px 0 6px;font-size:13px;font-weight:700;color:var(--text-primary)' : 'margin:16px 0 6px;font-size:13px;font-weight:700;color:#1e293b';
    const ths = cssVars
        ? 'padding:7px 12px;border:1px solid var(--border);background:var(--bg-surface);font-weight:700;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.04em'
        : 'padding:7px 12px;border:1px solid #e2e8f0;background:#f1f5f9;font-weight:700;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.04em';
    const tds = cssVars ? 'padding:7px 12px;border:1px solid var(--border);vertical-align:top' : 'padding:7px 12px;border:1px solid #e2e8f0;vertical-align:top';
    const hrs = cssVars ? 'border:none;border-top:1px solid var(--border);margin:16px 0' : 'border:none;border-top:1px solid #e2e8f0;margin:16px 0';
    const bqs = cssVars ? 'border-left:3px solid var(--brand);margin:10px 0;padding:8px 14px;background:var(--bg-surface);font-style:italic;font-size:12px' : 'border-left:3px solid #D04A02;margin:10px 0;padding:8px 14px;background:#f8fafc;font-style:italic;font-size:12px';

    const lines = md.split('\n');
    const out: string[] = [];
    let i = 0;
    while (i < lines.length) {
        const line = lines[i].trimEnd();
        if (line.startsWith('```')) {
            i++;
            const clines: string[] = [];
            while (i < lines.length && !lines[i].startsWith('```')) {
                clines.push(lines[i].replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'));
                i++;
            }
            const pres = cssVars
                ? 'background:var(--bg-surface);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-family:monospace;font-size:12px;overflow-x:auto;margin:8px 0'
                : 'background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:10px 14px;font-family:monospace;font-size:12px;overflow-x:auto;margin:8px 0';
            out.push(`<pre style="${pres}"><code>${clines.join('\n')}</code></pre>`);
            i++; continue;
        }
        if (/^# /.test(line)) {
            const h1s = cssVars ? 'font-size:20px;font-weight:800;color:var(--text-primary);margin:0 0 6px' : 'font-size:20px;font-weight:800;color:#0f172a;margin:0 0 6px';
            out.push(`<h1 style="${h1s}">${inline(line.slice(2))}</h1>`); i++; continue;
        }
        if (/^## /.test(line)) { out.push(`<h2 style="${h2s}">${inline(line.slice(3))}</h2>`); i++; continue; }
        if (/^### /.test(line)) { out.push(`<h3 style="${h3s}">${inline(line.slice(4))}</h3>`); i++; continue; }
        if (/^#### /.test(line)) { out.push(`<h4 style="margin:12px 0 4px;font-size:12px;font-weight:700">${inline(line.slice(5))}</h4>`); i++; continue; }
        if (/^---+$/.test(line.trim())) { out.push(`<hr style="${hrs}">`); i++; continue; }
        if (line.trim().startsWith('|')) {
            const tlines: string[] = [];
            while (i < lines.length && lines[i].trim().startsWith('|')) { tlines.push(lines[i]); i++; }
            let tHtml = `<table style="border-collapse:collapse;width:100%;font-size:12px;margin:12px 0">`;
            let hDone = false;
            for (const tl of tlines) {
                if (tl.split('|').filter(Boolean).every(c => /^[\s\-:]+$/.test(c))) continue;
                const cells = tl.split('|').filter(Boolean).map(c => c.trim());
                if (!hDone) {
                    tHtml += `<thead><tr>${cells.map(c => `<th style="${ths}">${inline(c)}</th>`).join('')}</tr></thead><tbody>`;
                    hDone = true;
                } else {
                    tHtml += `<tr>${cells.map(c => `<td style="${tds}">${inline(c)}</td>`).join('')}</tr>`;
                }
            }
            tHtml += hDone ? '</tbody></table>' : '</table>';
            out.push(tHtml); continue;
        }
        if (/^[-*] /.test(line)) {
            let ul = `<ul style="padding-left:22px;margin:8px 0">`;
            while (i < lines.length && /^[-*] /.test(lines[i])) {
                ul += `<li style="margin:4px 0;font-size:13px;line-height:1.6">${inline(lines[i].replace(/^[-*] /, ''))}</li>`; i++;
            }
            out.push(ul + '</ul>'); continue;
        }
        if (/^\d+\. /.test(line)) {
            let ol = '<ol style="padding-left:22px;margin:8px 0">';
            while (i < lines.length && /^\d+\. /.test(lines[i])) {
                ol += `<li style="margin:4px 0;font-size:13px;line-height:1.6">${inline(lines[i].replace(/^\d+\. /, ''))}</li>`; i++;
            }
            out.push(ol + '</ol>'); continue;
        }
        if (/^> /.test(line)) { out.push(`<blockquote style="${bqs}">${inline(line.slice(2))}</blockquote>`); i++; continue; }
        if (line.trim() === '') { out.push('<div style="height:6px"></div>'); i++; continue; }
        out.push(`<p style="margin:5px 0;font-size:13px;line-height:1.7">${inline(line)}</p>`); i++;
    }
    return out.join('\n');
}

function buildReportHtml(analysis: string, days: number, generatedAt: string): string {
    const body = markdownToHtml(analysis, false);
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DCR Assessment &amp; Injection Optimisation Report</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:0;margin:0;color:#1e293b;background:#f8fafc}
  .page{max-width:960px;margin:0 auto;padding:48px 40px}
  .report-header{background:linear-gradient(135deg,#D04A02 0%,#b83d01 100%);color:#fff;padding:32px 40px;margin:-48px -40px 36px}
  .report-header h1{font-size:24px;font-weight:800;margin:0 0 6px;color:#fff}
  .report-header .meta{font-size:12px;opacity:0.85;margin:0}
  .confidential{display:inline-block;margin-top:10px;padding:3px 10px;background:rgba(255,255,255,0.2);border-radius:4px;font-size:10px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase}
  h2{color:#D04A02;margin:28px 0 10px;font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;border-bottom:2px solid #D04A02;padding-bottom:6px}
  h3{margin:18px 0 6px;font-size:13px;font-weight:700;color:#1e293b}
  h4{margin:12px 0 4px;font-size:12px;font-weight:700}
  p{margin:5px 0;font-size:13px;line-height:1.7;color:#334155}
  ul,ol{padding-left:22px;margin:8px 0}
  li{margin:4px 0;font-size:13px;line-height:1.6}
  blockquote{border-left:3px solid #D04A02;margin:10px 0;padding:8px 14px;background:#f8fafc;font-style:italic;font-size:12px;color:#475569}
  table{border-collapse:collapse;width:100%;font-size:12px;margin:12px 0}
  th{padding:7px 12px;border:1px solid #e2e8f0;background:#f1f5f9;font-weight:700;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.04em;color:#475569}
  td{padding:7px 12px;border:1px solid #e2e8f0;vertical-align:top;color:#334155}
  tr:nth-child(even) td{background:#f8fafc}
  code{background:#f1f5f9;padding:1px 6px;border-radius:3px;font-size:11px;font-family:monospace;color:#0f172a}
  pre{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:12px 16px;font-size:12px;overflow-x:auto;margin:10px 0}
  hr{border:none;border-top:1px solid #e2e8f0;margin:18px 0}
  strong{font-weight:700} em{font-style:italic}
  .footer{margin-top:40px;padding-top:16px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;font-size:11px;color:#94a3b8}
  @media print{.report-header{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>
</head>
<body>
<div class="page">
  <div class="report-header">
    <h1>DCR Assessment &amp; Injection Optimisation Report</h1>
    <p class="meta">Period: Last ${days} days &nbsp;·&nbsp; Generated: ${new Date(generatedAt).toLocaleString()}</p>
    <span class="confidential">Confidential — Internal Use Only</span>
  </div>
  <div class="report-body">${body}</div>
  <div class="footer">
    <span>Sentinel Vigil · Microsoft Sentinel</span>
    <span>DCR Assessment Report · ${new Date(generatedAt).toLocaleString()}</span>
  </div>
</div>
</body>
</html>`;
}

// ── AI Report Panel ───────────────────────────────────────────────────────────
interface TokenUsage { input_tokens: number; output_tokens: number; model: string; }

function AiReportPanel({ days }: { days: number }) {
    const [loading, setLoading] = useState(false);
    const [report, setReport] = useState<{ llm_analysis: string; generated_at: string; token_usage?: TokenUsage } | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [expanded, setExpanded] = useState(true);

    const generate = async () => {
        setLoading(true); setError(null); setReport(null);
        try {
            const res = await axios.get(`/api/dcr/report?days=${days}`, { timeout: 0 });
            setReport(res.data);
            setExpanded(true);
        } catch (e: any) {
            setError(e.response?.data?.detail || e.message || 'Report generation failed');
        } finally { setLoading(false); }
    };

    const exportHtml = async () => {
        if (!report) return;
        const html = buildReportHtml(report.llm_analysis, days, report.generated_at);
        try {
            const res = await axios.post('/api/reports/export-html',
                { html, filename: `DCR_Assessment_Report_${days}d.html` },
                { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url;
            a.download = `DCR_Assessment_Report_${days}d.html`; a.click(); a.remove();
        } catch (e: any) { setError(`HTML export failed: ${e.message}`); }
    };

    const exportPdf = async () => {
        if (!report) return;
        const html = buildReportHtml(report.llm_analysis, days, report.generated_at);
        try {
            const res = await axios.post('/api/reports/export-pdf',
                { html, filename: `DCR_Assessment_Report_${days}d.pdf` },
                { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url;
            a.download = `DCR_Assessment_Report_${days}d.pdf`; a.click(); a.remove();
        } catch (e: any) { setError(`PDF export failed: ${e.message}`); }
    };

    return (
        <div className="card" style={{ border: '1.5px solid var(--brand)', marginBottom: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: report ? 12 : 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <FontAwesomeIcon icon={faRobot} style={{ color: 'var(--brand)', fontSize: 18 }} />
                    <div>
                        <div style={{ fontWeight: 700, fontSize: 14 }}>AI DCR Assessment & Ingestion Optimisation Report</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            LLM-powered analysis across all DCR telemetry — last {days} days
                        </div>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    {report && (
                        <>
                            <button className="btn btn-sm btn-ghost" onClick={exportHtml}>
                                <FontAwesomeIcon icon={faFileCode} style={{ color: 'var(--info)' }} /> HTML
                            </button>
                            <button className="btn btn-sm btn-ghost" onClick={exportPdf}>
                                <FontAwesomeIcon icon={faFilePdf} style={{ color: 'var(--critical)' }} /> PDF
                            </button>
                            <button className="btn btn-sm btn-ghost" onClick={() => setExpanded(e => !e)}>
                                <FontAwesomeIcon icon={expanded ? faChevronUp : faChevronDown} />
                            </button>
                        </>
                    )}
                    <button className="btn btn-sm btn-primary" onClick={generate} disabled={loading}>
                        <FontAwesomeIcon icon={faRobot} spin={loading} style={{ marginRight: 6 }} />
                        {loading ? 'Generating…' : report ? 'Regenerate' : 'Generate Report'}
                    </button>
                </div>
            </div>

            {loading && (
                <div style={{ padding: '20px 0', display: 'flex', alignItems: 'center', gap: 12, color: 'var(--text-muted)', fontSize: 13 }}>
                    <div className="spinner" />
                    Gathering DCR telemetry and running LLM analysis — this may take 20–40 seconds…
                </div>
            )}

            {error && (
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
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'monospace', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: '2px 8px', color: 'var(--text-muted)' }}>
                                <FontAwesomeIcon icon={faBolt} style={{ color: 'var(--warning)', fontSize: 9 }} />
                                <span style={{ color: 'var(--info)' }}>{report.token_usage.input_tokens.toLocaleString()}</span>
                                <span>in</span>
                                <span style={{ opacity: 0.5 }}>→</span>
                                <span style={{ color: 'var(--success, #27ae60)' }}>{report.token_usage.output_tokens.toLocaleString()}</span>
                                <span>out</span>
                                <span style={{ opacity: 0.4 }}>·</span>
                                <span style={{ opacity: 0.7 }}>{report.token_usage.model}</span>
                            </span>
                        )}
                    </div>
                    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: '20px 24px', lineHeight: 1.7 }}
                        dangerouslySetInnerHTML={{ __html: markdownToHtml(report.llm_analysis) }} />
                </div>
            )}
        </div>
    );
}

// ── Stat Card ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
    return (
        <div className="card" style={{ flex: '1 1 160px', minWidth: 140 }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
            <div style={{ fontSize: 26, fontWeight: 800, color: color || 'var(--text-primary)', lineHeight: 1 }}>{value}</div>
            {sub && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{sub}</div>}
        </div>
    );
}

// ── State badge ───────────────────────────────────────────────────────────────
function StateBadge({ state }: { state: string }) {
    const ok = state === 'Succeeded';
    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 10,
            background: ok ? 'rgba(39,174,96,0.12)' : 'rgba(192,57,43,0.12)',
            color: ok ? '#27AE60' : '#C0392B',
        }}>
            <FontAwesomeIcon icon={ok ? faCircleCheck : faCircleXmark} />
            {state || 'Unknown'}
        </span>
    );
}

// ── Mini bar ──────────────────────────────────────────────────────────────────
function MiniBar({ pct, color }: { pct: number; color?: string }) {
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ flex: 1, height: 6, background: 'var(--bg-surface)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${Math.min(100, pct)}%`, height: '100%', background: color || 'var(--brand)', borderRadius: 3 }} />
            </div>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', minWidth: 32 }}>{pct}%</span>
        </div>
    );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function DcrAssessment() {
    const [tab, setTab] = useState<TabId>('overview');
    const [days, setDays] = useState(30);
    const [overview, setOverview] = useState<Overview | null>(null);
    const [rulesData, setRulesData] = useState<DcrRulesData | null>(null);
    const [ingestion, setIngestion] = useState<IngestionData | null>(null);
    const [errorsData, setErrorsData] = useState<ErrorsData | null>(null);
    const [activity, setActivity] = useState<ActivityItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const fetchData = async () => {
        setLoading(true); setError(null);
        try {
            const [ov, rules, ing, errs, act] = await Promise.all([
                axios.get(`/api/dcr/overview?days=${days}`),
                axios.get('/api/dcr/rules'),
                axios.get(`/api/dcr/ingestion?days=${days}`),
                axios.get(`/api/dcr/errors?days=${days}`),
                axios.get(`/api/dcr/activity?days=${days}`),
            ]);
            setOverview(ov.data);
            setRulesData(rules.data);
            setIngestion(ing.data);
            setErrorsData(errs.data);
            setActivity(act.data.activity || []);
        } catch (e: any) {
            setError(e.response?.data?.detail || e.message || 'Failed to load DCR data');
        } finally { setLoading(false); }
    };

    useEffect(() => { fetchData(); }, [days]);

    const rules = rulesData?.rules || [];
    const byTable = ingestion?.by_table || [];
    const ingSum = ingestion?.summary;
    const dcrErrors = errorsData?.errors || [];
    const diag = errorsData?.diagnostics || [];
    const trend = ingestion?.daily_trend || [];
    const maxMb = Math.max(...byTable.map(t => t.total_mb), 1);

    const TABS: { id: TabId; label: string }[] = [
        { id: 'overview', label: 'Overview' },
        { id: 'inventory', label: 'DCR Inventory' },
        { id: 'ingestion', label: 'Ingestion' },
        { id: 'errors', label: 'Errors & Drops' },
        { id: 'activity', label: 'Activity' },
        { id: 'ai', label: 'AI Report' },
    ];

    return (
        <div style={{ padding: '24px 28px', maxWidth: 1400, margin: '0 auto' }}>
            {/* ── Header ── */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
                        <FontAwesomeIcon icon={faDatabase} style={{ fontSize: 22, color: 'var(--brand)' }} />
                        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>DCR Assessment & Ingestion Optimisation</h1>
                    </div>
                    <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                        Data Collection Rules inventory, ingestion volume, transformation coverage, and cost analysis
                    </div>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <select
                        value={days}
                        onChange={e => setDays(+e.target.value)}
                        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '5px 10px', color: 'var(--text-primary)', fontSize: 12 }}
                    >
                        {[7, 14, 30, 60, 90].map(d => <option key={d} value={d}>Last {d} days</option>)}
                    </select>
                    <button className="btn btn-sm btn-ghost" onClick={fetchData} disabled={loading}>
                        <FontAwesomeIcon icon={faRefresh} spin={loading} />
                    </button>
                </div>
            </div>

            {error && (
                <div style={{ marginBottom: 16, padding: '10px 14px', background: 'rgba(192,57,43,0.07)', border: '1px solid rgba(192,57,43,0.25)', borderRadius: 8, fontSize: 12, color: 'var(--critical)' }}>
                    <FontAwesomeIcon icon={faCircleXmark} style={{ marginRight: 8 }} />{error}
                </div>
            )}

            {/* ── KPI Row ── */}
            {overview && (
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 24 }}>
                    <StatCard label="Total DCRs" value={overview.dcr_total} sub={`${overview.dcr_succeeded} succeeded`} />
                    <StatCard label="With Transforms" value={overview.dcr_with_transforms} sub={`of ${overview.dcr_total} DCRs`} color="var(--brand)" />
                    <StatCard label="Data Flows" value={overview.total_data_flows} sub={`${overview.total_transformations} KQL transforms`} />
                    <StatCard label="Ingestion (period)" value={`${overview.ingestion_total_gb} GB`} sub={`${overview.ingestion_tables} tables`} />
                    <StatCard label="Est. Monthly" value={`${overview.estimated_monthly_gb} GB`} sub={`~$${(overview.estimated_monthly_gb * 2.76).toFixed(0)}/mo`} color="var(--warning)" />
                    <StatCard label="DCR Errors" value={overview.total_errors} sub={`${overview.affected_rules} rules affected`} color={overview.total_errors > 0 ? 'var(--critical)' : undefined} />
                    {overview.dcr_failed > 0 && (
                        <StatCard label="Failed DCRs" value={overview.dcr_failed} sub="need attention" color="var(--critical)" />
                    )}
                </div>
            )}

            {/* ── Tabs ── */}
            <div style={{ display: 'flex', gap: 4, marginBottom: 20, borderBottom: '1px solid var(--border)', paddingBottom: 0 }}>
                {TABS.map(t => (
                    <button
                        key={t.id}
                        onClick={() => setTab(t.id)}
                        style={{
                            padding: '8px 16px', fontSize: 12, fontWeight: 600, border: 'none', cursor: 'pointer',
                            borderRadius: '6px 6px 0 0', transition: 'all 0.15s',
                            background: tab === t.id ? 'var(--brand)' : 'transparent',
                            color: tab === t.id ? '#fff' : 'var(--text-muted)',
                            borderBottom: tab === t.id ? '2px solid var(--brand)' : '2px solid transparent',
                        }}
                    >
                        {t.label}
                    </button>
                ))}
            </div>

            {loading && tab !== 'ai' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, color: 'var(--text-muted)', padding: '40px 0', justifyContent: 'center' }}>
                    <div className="spinner" />
                    Loading DCR telemetry…
                </div>
            )}

            {/* ── Overview Tab ── */}
            {!loading && tab === 'overview' && overview && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                        {/* DCR Health */}
                        <div className="card" style={{ flex: '1 1 320px' }}>
                            <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 14 }}>DCR Health Summary</div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                {[
                                    { label: 'Succeeded', val: overview.dcr_succeeded, total: overview.dcr_total, color: '#27AE60' },
                                    { label: 'With KQL Transforms', val: overview.dcr_with_transforms, total: overview.dcr_total, color: 'var(--brand)' },
                                    { label: 'Custom Streams', val: overview.dcr_custom_streams, total: overview.dcr_total, color: 'var(--info)' },
                                ].map(row => (
                                    <div key={row.label}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                                            <span style={{ color: 'var(--text-muted)' }}>{row.label}</span>
                                            <span style={{ fontWeight: 700 }}>{row.val} / {row.total}</span>
                                        </div>
                                        <MiniBar pct={row.total > 0 ? Math.round(100 * row.val / row.total) : 0} color={row.color} />
                                    </div>
                                ))}
                                {overview.dcr_failed > 0 && (
                                    <div style={{ marginTop: 6, padding: '8px 12px', background: 'rgba(192,57,43,0.07)', borderRadius: 6, fontSize: 12, color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <FontAwesomeIcon icon={faTriangleExclamation} />
                                        {overview.dcr_failed} DCR(s) in failed state — review required
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Ingestion summary */}
                        <div className="card" style={{ flex: '1 1 320px' }}>
                            <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 14 }}>Ingestion Summary</div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                {[
                                    { label: 'Total (period)', val: `${overview.ingestion_total_gb} GB` },
                                    { label: 'Daily average', val: `${overview.ingestion_daily_avg_mb} MB/day` },
                                    { label: 'Active tables', val: `${overview.ingestion_tables}` },
                                    { label: 'Est. monthly', val: `${overview.estimated_monthly_gb} GB` },
                                    { label: 'Est. monthly cost', val: `$${(overview.estimated_monthly_gb * 2.76).toFixed(2)}` },
                                ].map(row => (
                                    <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, borderBottom: '1px solid var(--border)', paddingBottom: 6 }}>
                                        <span style={{ color: 'var(--text-muted)' }}>{row.label}</span>
                                        <span style={{ fontWeight: 700 }}>{row.val}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Errors */}
                        <div className="card" style={{ flex: '1 1 260px' }}>
                            <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 14 }}>Pipeline Errors</div>
                            {overview.total_errors === 0 ? (
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#27AE60', fontSize: 13 }}>
                                    <FontAwesomeIcon icon={faCheckCircle} />
                                    No DCR errors detected
                                </div>
                            ) : (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                                        <span style={{ color: 'var(--text-muted)' }}>Total error events</span>
                                        <span style={{ fontWeight: 700, color: 'var(--critical)' }}>{overview.total_errors}</span>
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                                        <span style={{ color: 'var(--text-muted)' }}>Affected DCR rules</span>
                                        <span style={{ fontWeight: 700, color: 'var(--critical)' }}>{overview.affected_rules}</span>
                                    </div>
                                    <div style={{ marginTop: 4, padding: '7px 10px', background: 'rgba(192,57,43,0.07)', borderRadius: 6, fontSize: 11, color: 'var(--critical)' }}>
                                        <FontAwesomeIcon icon={faExclamationCircle} style={{ marginRight: 6 }} />
                                        Check the Errors & Drops tab for details
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Ingestion trend */}
                    {trend.length > 0 && (() => {
                        const maxTrend = Math.max(...trend.map(t => Number(t.total_mb)), 1);
                        return (
                            <div className="card">
                                <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 14 }}>Daily Ingestion Trend</div>
                                <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 80, background: 'var(--bg-surface)', borderRadius: 6, padding: '4px 4px 0' }}>
                                    {trend.slice(-30).map((d, i) => {
                                        const h = Math.max(2, Math.round((Number(d.total_mb) / maxTrend) * 72));
                                        return (
                                            <div key={i} title={`${d.date}: ${d.total_mb} MB`}
                                                style={{ flex: 1, height: h, alignSelf: 'flex-end', background: 'var(--brand)', borderRadius: '2px 2px 0 0', opacity: 0.85, minWidth: 2 }} />
                                        );
                                    })}
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                                    <span>{trend[0]?.date}</span>
                                    <span>{trend[trend.length - 1]?.date}</span>
                                </div>
                            </div>
                        );
                    })()}
                </div>
            )}

            {/* ── Inventory Tab ── */}
            {!loading && tab === 'inventory' && (
                <div className="card" style={{ padding: 0 }}>
                    <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', fontWeight: 700, fontSize: 13 }}>
                        DCR Inventory — {rules.length} rule{rules.length !== 1 ? 's' : ''}
                        {rulesData?.error && (
                            <span style={{ marginLeft: 10, fontSize: 11, color: 'var(--critical)' }}>
                                <FontAwesomeIcon icon={faInfoCircle} style={{ marginRight: 4 }} />
                                {rulesData.error}
                            </span>
                        )}
                    </div>
                    {rules.length === 0 ? (
                        <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                            No DCRs found. Ensure the service principal has Reader access to the subscription.
                        </div>
                    ) : (
                        <div style={{ overflowX: 'auto' }}>
                            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                                <thead>
                                    <tr style={{ background: 'var(--bg-surface)' }}>
                                        {['Name', 'Location', 'State', 'Flows', 'Transforms', 'Custom Streams', 'KQL?', 'Days Since Modified'].map(h => (
                                            <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap' }}>{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {rules.map((r, i) => (
                                        <tr key={r.id} style={{ borderBottom: '1px solid var(--border)', background: i % 2 === 1 ? 'var(--bg-surface)' : undefined }}>
                                            <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 11 }}>{r.name}</td>
                                            <td style={{ padding: '8px 12px', color: 'var(--text-muted)' }}>{r.location}</td>
                                            <td style={{ padding: '8px 12px' }}><StateBadge state={r.provisioning_state} /></td>
                                            <td style={{ padding: '8px 12px', textAlign: 'center' }}>{r.data_flows}</td>
                                            <td style={{ padding: '8px 12px', textAlign: 'center' }}>{r.transformations}</td>
                                            <td style={{ padding: '8px 12px', textAlign: 'center' }}>{r.custom_streams}</td>
                                            <td style={{ padding: '8px 12px' }}>
                                                {r.has_transformation
                                                    ? <span style={{ color: '#27AE60', fontWeight: 700, fontSize: 11 }}>Yes</span>
                                                    : <span style={{ color: 'var(--warning)', fontWeight: 700, fontSize: 11 }}>No</span>}
                                            </td>
                                            <td style={{ padding: '8px 12px', color: (r.days_since_modified ?? 0) > 90 ? 'var(--warning)' : 'var(--text-muted)' }}>
                                                {r.days_since_modified !== null ? `${r.days_since_modified}d` : '—'}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}

            {/* ── Ingestion Tab ── */}
            {!loading && tab === 'ingestion' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    {ingSum && (
                        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                            <StatCard label="Total Volume" value={`${ingSum.total_gb} GB`} sub={`${ingSum.total_mb} MB`} />
                            <StatCard label="Daily Average" value={`${ingSum.daily_avg_mb} MB`} sub="per day" />
                            <StatCard label="Active Tables" value={ingSum.table_count} sub="billable" />
                            <StatCard label="Est. Monthly" value={`${ingSum.estimated_monthly_gb} GB`} sub="projected" color="var(--warning)" />
                            <StatCard label="Est. Cost/Month" value={`$${(ingSum.estimated_monthly_gb * 2.76).toFixed(2)}`} sub="at $2.76/GB" color="var(--warning)" />
                        </div>
                    )}
                    <div className="card" style={{ padding: 0 }}>
                        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', fontWeight: 700, fontSize: 13 }}>
                            Ingestion by Table — top {byTable.length}
                        </div>
                        {byTable.length === 0 ? (
                            <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>No ingestion data available</div>
                        ) : (
                            <div>
                                {byTable.map((t, i) => (
                                    <div key={t.table} style={{ padding: '10px 18px', borderBottom: '1px solid var(--border)', background: i % 2 === 1 ? 'var(--bg-surface)' : undefined }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                                            <span style={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 600 }}>{t.table}</span>
                                            <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-muted)' }}>
                                                <span><strong style={{ color: 'var(--text-primary)' }}>{t.total_mb} MB</strong> total</span>
                                                <span><strong style={{ color: 'var(--text-primary)' }}>{t.daily_avg} MB</strong>/day</span>
                                                <span style={{ color: 'var(--brand)', fontWeight: 700 }}>{t.pct}%</span>
                                            </div>
                                        </div>
                                        <div style={{ height: 5, background: 'var(--bg-surface)', borderRadius: 3, overflow: 'hidden' }}>
                                            <div style={{ width: `${Math.round(100 * t.total_mb / maxMb)}%`, height: '100%', background: 'var(--brand)', borderRadius: 3, opacity: 0.8 }} />
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* ── Errors Tab ── */}
            {!loading && tab === 'errors' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    {errorsData && (
                        <div style={{ display: 'flex', gap: 12 }}>
                            <StatCard label="Total Errors" value={errorsData.total_errors} color={errorsData.total_errors > 0 ? 'var(--critical)' : undefined} />
                            <StatCard label="Affected Rules" value={errorsData.affected_rules} color={errorsData.affected_rules > 0 ? 'var(--warning)' : undefined} />
                        </div>
                    )}

                    {/* DCRLogErrors */}
                    <div className="card" style={{ padding: 0 }}>
                        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', fontWeight: 700, fontSize: 13 }}>
                            DCR Pipeline Errors (DCRLogErrors)
                        </div>
                        {dcrErrors.length === 0 ? (
                            <div style={{ padding: 24, textAlign: 'center', color: '#27AE60', fontSize: 13 }}>
                                <FontAwesomeIcon icon={faCheckCircle} style={{ marginRight: 8 }} />
                                No pipeline errors detected
                            </div>
                        ) : (
                            <div style={{ overflowX: 'auto' }}>
                                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                                    <thead>
                                        <tr style={{ background: 'var(--bg-surface)' }}>
                                            {['Rule Name', 'Stream', 'Error Code', 'Message', 'Count', 'Last Seen'].map(h => (
                                                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em', borderBottom: '1px solid var(--border)' }}>{h}</th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {dcrErrors.map((e, i) => (
                                            <tr key={i} style={{ borderBottom: '1px solid var(--border)', background: i % 2 === 1 ? 'var(--bg-surface)' : undefined }}>
                                                <td style={{ padding: '7px 12px', fontFamily: 'monospace', fontSize: 11 }}>{e.rule_name}</td>
                                                <td style={{ padding: '7px 12px', color: 'var(--text-muted)' }}>{e.stream}</td>
                                                <td style={{ padding: '7px 12px' }}>
                                                    {e.error_code && <span style={{ background: 'rgba(192,57,43,0.1)', color: 'var(--critical)', padding: '1px 6px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace' }}>{e.error_code}</span>}
                                                </td>
                                                <td style={{ padding: '7px 12px', maxWidth: 280, color: 'var(--text-muted)' }}>{e.message}</td>
                                                <td style={{ padding: '7px 12px', fontWeight: 700, color: 'var(--critical)' }}>{e.count}</td>
                                                <td style={{ padding: '7px 12px', color: 'var(--text-muted)', fontSize: 11 }}>{e.last_seen ? e.last_seen.slice(0, 10) : '—'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>

                    {/* Diagnostics */}
                    {diag.length > 0 && (
                        <div className="card" style={{ padding: 0 }}>
                            <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', fontWeight: 700, fontSize: 13 }}>
                                AzureDiagnostics — DCR Events
                            </div>
                            <div style={{ overflowX: 'auto' }}>
                                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                                    <thead>
                                        <tr style={{ background: 'var(--bg-surface)' }}>
                                            {['Operation', 'Resource', 'Result', 'Count'].map(h => (
                                                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em', borderBottom: '1px solid var(--border)' }}>{h}</th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {diag.map((d, i) => (
                                            <tr key={i} style={{ borderBottom: '1px solid var(--border)', background: i % 2 === 1 ? 'var(--bg-surface)' : undefined }}>
                                                <td style={{ padding: '7px 12px', fontFamily: 'monospace', fontSize: 11 }}>{d.operation.split('/').pop()}</td>
                                                <td style={{ padding: '7px 12px', color: 'var(--text-muted)' }}>{d.resource}</td>
                                                <td style={{ padding: '7px 12px' }}>
                                                    <span style={{ color: d.result === 'Success' ? '#27AE60' : 'var(--critical)', fontWeight: 700, fontSize: 11 }}>{d.result}</span>
                                                </td>
                                                <td style={{ padding: '7px 12px', fontWeight: 700 }}>{d.count}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── Activity Tab ── */}
            {!loading && tab === 'activity' && (
                <div className="card" style={{ padding: 0 }}>
                    <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', fontWeight: 700, fontSize: 13 }}>
                        DCR Governance Activity — last {days} days
                    </div>
                    {activity.length === 0 ? (
                        <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                            No DCR activity events found in AzureActivity for this period
                        </div>
                    ) : (
                        <div style={{ overflowX: 'auto' }}>
                            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                                <thead>
                                    <tr style={{ background: 'var(--bg-surface)' }}>
                                        {['Operation', 'Resource', 'Status', 'Caller', 'Count', 'Last Seen'].map(h => (
                                            <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em', borderBottom: '1px solid var(--border)' }}>{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {activity.map((a, i) => (
                                        <tr key={i} style={{ borderBottom: '1px solid var(--border)', background: i % 2 === 1 ? 'var(--bg-surface)' : undefined }}>
                                            <td style={{ padding: '7px 12px', fontFamily: 'monospace', fontSize: 11 }}>{a.operation.split('/').pop()}</td>
                                            <td style={{ padding: '7px 12px', color: 'var(--text-muted)' }}>{a.resource}</td>
                                            <td style={{ padding: '7px 12px' }}>
                                                <span style={{ color: a.status === 'Success' ? '#27AE60' : 'var(--critical)', fontWeight: 700, fontSize: 11 }}>{a.status}</span>
                                            </td>
                                            <td style={{ padding: '7px 12px', color: 'var(--text-muted)' }}>{a.caller}</td>
                                            <td style={{ padding: '7px 12px', fontWeight: 700 }}>{a.count}</td>
                                            <td style={{ padding: '7px 12px', color: 'var(--text-muted)', fontSize: 11 }}>{a.last_seen ? a.last_seen.slice(0, 10) : '—'}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}

            {/* ── AI Report Tab ── */}
            {tab === 'ai' && <AiReportPanel days={days} />}
        </div>
    );
}
