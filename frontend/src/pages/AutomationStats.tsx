import { useState, useEffect } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { ReportLogPanel, type LogStep } from '../components/ReportLogPanel';
import {
    faWandMagicSparkles, faPlay, faCircleCheck, faCircleXmark,
    faChartPie, faListCheck, faFilePdf, faFileCode, faRefresh,
    faServer, faShieldHalved, faTriangleExclamation, faCheck,
    faXmark, faBolt, faRobot, faChevronDown, faChevronUp,
} from '@fortawesome/free-solid-svg-icons';

// ── Types ─────────────────────────────────────────────────────────────────────
interface Overview {
    playbook_runs: number; playbook_success: number; playbook_failed: number;
    success_rate: number; incident_total: number; true_positive: number;
    false_positive: number; benign_positive: number; undetermined: number;
}
interface Playbook {
    name: string; total_runs: number; succeeded: number;
    failed: number; success_rate: number; last_run: string;
}
interface Classification { label: string; count: number; }
interface DayPoint { date: string; created: number; closed: number; }
interface SoarRow {
    status: string; total: number; with_owner: number;
    without_owner: number; high_severity: number; auto_labeled: number;
}
interface LogicApp {
    name: string; state: string; trigger_type: string;
    created_time: string; changed_time: string;
    total_runs: number; succeeded: number; failed: number;
    success_rate: number | null; last_run: string;
    location: string; tags: Record<string, string>;
}
interface LogicAppsData {
    logic_apps: LogicApp[]; enabled_count: number;
    disabled_count: number; total_count: number; mgmt_error?: string;
}
interface AutomationRule {
    id: string; display_name: string; enabled: boolean; order: number;
    trigger_kind: string; trigger_when: string;
    conditions: Array<{ property: string; operator: string; values: string[] }>;
    actions: Array<{ order: number; type: string; playbook?: string; changes?: Record<string, unknown> }>;
    created_time: string; last_modified: string;
}
interface AutomationRulesData {
    rules: AutomationRule[]; total: number;
    enabled_count: number; disabled_count: number; playbook_rules: number;
}
interface FailureEntry { name: string; failed_runs: number; last_failure: string; }
interface FailureTrendPoint { date: string; total: number; failed: number; succeeded: number; }
interface FailureReason { error_code: string; error_message: string; count: number; }
interface FailuresData {
    by_playbook: FailureEntry[]; daily_trend: FailureTrendPoint[];
    failure_reasons: FailureReason[]; total_failures: number;
}

type TabId = 'overview' | 'playbooks' | 'outcomes' | 'soar' | 'logicapps' | 'rules' | 'failures' | 'ai';

const CLASS_COLORS: Record<string, string> = {
    TruePositive: '#27AE60', FalsePositive: '#C0392B',
    BenignPositive: '#F39C12', Undetermined: '#7F8C8D', Unclassified: '#BDC3C7',
};

// ── AI Report Panel ───────────────────────────────────────────────────────────
interface TokenUsage { input_tokens: number; output_tokens: number; model: string; }

const AUTOMATION_LOG_STEPS: LogStep[] = [
    { level: 'info', msg: 'Connecting to Sentinel workspace…',           delay: 400 },
    { level: 'info', msg: 'Fetching automation rule telemetry…',         delay: 2500 },
    { level: 'info', msg: 'Pulling playbook run statistics…',            delay: 5000 },
    { level: 'info', msg: 'Querying SOAR incident metrics…',             delay: 7500 },
    { level: 'info', msg: 'Analysing threat response patterns…',         delay: 10500 },
    { level: 'ai',   msg: 'Running LLM analysis with Claude…',           delay: 13500 },
    { level: 'ai',   msg: 'Structuring SOAR recommendations…',           delay: 18000 },
];

function AiReportPanel({ days }: { days: number }) {
    const [loading, setLoading]   = useState(false);
    const [success, setSuccess]   = useState<boolean | null>(null);
    const [report, setReport]     = useState<{ llm_analysis: string; generated_at: string; token_usage?: TokenUsage } | null>(null);
    const [error, setError]       = useState<string | null>(null);
    const [expanded, setExpanded] = useState(true);
    const [model, setModel]       = useState('claude-sonnet-4-6');

    const generate = async () => {
        setLoading(true); setError(null); setReport(null); setSuccess(null);
        try {
            const res = await axios.get(`/api/automation/report?days=${days}&model=${model}`, { timeout: 0 });
            setReport(res.data);
            setExpanded(true);
            setSuccess(true);
        } catch (e: any) {
            setError(e.response?.data?.detail || e.message || 'Report generation failed');
            setSuccess(false);
        } finally { setLoading(false); }
    };

    const exportHtml = async () => {
        if (!report) return;
        const html = buildReportHtml(report.llm_analysis, days, report.generated_at);
        try {
            const res = await axios.post('/api/reports/export-html',
                { html, filename: `Automation_SOAR_Report_${days}d.html` },
                { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url;
            a.download = `Automation_SOAR_Report_${days}d.html`; a.click(); a.remove();
        } catch (e: any) {
            setError(`HTML export failed: ${e.response?.data?.detail || e.message}`);
        }
    };

    const exportPdf = async () => {
        if (!report) return;
        const html = buildReportHtml(report.llm_analysis, days, report.generated_at);
        try {
            const res = await axios.post('/api/reports/export-pdf',
                { html, filename: `Automation_SOAR_Report_${days}d.pdf` },
                { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url;
            a.download = `Automation_SOAR_Report_${days}d.pdf`; a.click(); a.remove();
        } catch (e: any) {
            setError(`PDF export failed: ${e.response?.data?.detail || e.message}`);
        }
    };

    return (
        <div className="card" style={{ border: '1.5px solid var(--brand)', marginBottom: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: report ? 12 : 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <FontAwesomeIcon icon={faRobot} style={{ color: 'var(--brand)', fontSize: 18 }} />
                    <div>
                        <div style={{ fontWeight: 700, fontSize: 14 }}>AI Automation & SOAR Report</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            LLM-powered analysis across all data sources — last {days} days
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
                    <select
                        value={model}
                        onChange={e => setModel(e.target.value)}
                        disabled={loading}
                        style={{ fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', cursor: 'pointer' }}
                    >
                        <option value="claude-sonnet-4-6">Sonnet 4.6</option>
                        <option value="claude-haiku-4-5-20251001">Haiku 4.5</option>
                    </select>
                    <button className="btn btn-sm btn-primary" onClick={generate} disabled={loading}>
                        <FontAwesomeIcon icon={faRobot} spin={loading} style={{ marginRight: 6 }} />
                        {loading ? 'Generating…' : report ? 'Regenerate' : 'Generate Report'}
                    </button>
                </div>
            </div>

            <ReportLogPanel steps={AUTOMATION_LOG_STEPS} loading={loading} success={success} error={error} />

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
                            <span style={{
                                display: 'inline-flex', alignItems: 'center', gap: 5,
                                fontSize: 10, fontFamily: 'monospace',
                                background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                                borderRadius: 6, padding: '2px 8px', color: 'var(--text-muted)',
                            }}>
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
                    <div style={{
                        background: 'var(--bg-card)', border: '1px solid var(--border)',
                        borderRadius: 10, padding: '20px 24px', lineHeight: 1.7,
                    }}
                        dangerouslySetInnerHTML={{ __html: markdownToHtml(report.llm_analysis) }} />
                </div>
            )}
        </div>
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────
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
            const pres = cssVars ? 'background:var(--bg-surface);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-family:monospace;font-size:12px;overflow-x:auto;margin:8px 0' : 'background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:10px 14px;font-family:monospace;font-size:12px;overflow-x:auto;margin:8px 0';
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
        if (/^---+$/.test(line.trim()) || /^\*\*\*+$/.test(line.trim())) { out.push(`<hr style="${hrs}">`); i++; continue; }

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
<title>Automation &amp; SOAR Report</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:0;margin:0;color:#1e293b;background:#f8fafc}
  .page{max-width:960px;margin:0 auto;padding:48px 40px}
  .report-header{background:linear-gradient(135deg,#D04A02 0%,#b83d01 100%);color:#fff;padding:32px 40px;margin:-48px -40px 36px}
  .report-header h1{font-size:24px;font-weight:800;margin:0 0 6px;color:#fff}
  .report-header .meta{font-size:12px;opacity:0.85;margin:0}
  .confidential{display:inline-block;margin-top:10px;padding:3px 10px;background:rgba(255,255,255,0.2);border-radius:4px;font-size:10px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase}
  h1{font-size:20px;font-weight:800;color:#0f172a;margin:0 0 6px}
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
    <h1>Automation &amp; SOAR Comprehensive Report</h1>
    <p class="meta">Period: Last ${days} days &nbsp;·&nbsp; Generated: ${new Date(generatedAt).toLocaleString()}</p>
    <span class="confidential">Confidential — Internal Use Only</span>
  </div>
  <div class="report-body">${body}</div>
  <div class="footer">
    <span>Sentinel Vigil · Microsoft Sentinel</span>
    <span>Automation &amp; SOAR Report · ${new Date(generatedAt).toLocaleString()}</span>
  </div>
</div>
</body>
</html>`;
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function AutomationStats() {
    const [tab, setTab]       = useState<TabId>('overview');
    const [days, setDays]     = useState(30);
    const [overview, setOverview]   = useState<Overview | null>(null);
    const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
    const [classifications, setClassifications] = useState<Classification[]>([]);
    const [dailyTrend, setDailyTrend]   = useState<DayPoint[]>([]);
    const [soarActions, setSoarActions] = useState<SoarRow[]>([]);
    const [logicApps, setLogicApps]     = useState<LogicAppsData | null>(null);
    const [autoRules, setAutoRules]     = useState<AutomationRulesData | null>(null);
    const [failures, setFailures]       = useState<FailuresData | null>(null);
    const [loading, setLoading]         = useState(true);
    const [isExporting, setIsExporting] = useState(false);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [ov, pb, out, soar, la, ar, fail] = await Promise.all([
                axios.get(`/api/automation/overview?days=${days}`),
                axios.get(`/api/automation/playbooks?days=${days}`),
                axios.get(`/api/automation/outcomes?days=${days}`),
                axios.get(`/api/automation/soar-actions?days=${days}`),
                axios.get('/api/automation/logic-apps'),
                axios.get('/api/automation/automation-rules'),
                axios.get(`/api/automation/failures?days=${days}`),
            ]);
            setOverview(ov.data);
            setPlaybooks(pb.data.playbooks || []);
            setClassifications(out.data.classifications || []);
            setDailyTrend(out.data.daily_trend || []);
            setSoarActions(soar.data.by_status || []);
            setLogicApps(la.data);
            setAutoRules(ar.data);
            setFailures(fail.data);
        } catch (e) {
            console.error('AutomationStats fetch failed', e);
        } finally { setLoading(false); }
    };

    useEffect(() => { fetchData(); }, [days]);

    const totalClass = classifications.reduce((s, c) => s + c.count, 0);
    const maxRuns    = Math.max(...playbooks.map(p => p.total_runs), 1);
    const maxTrend   = Math.max(...dailyTrend.map(d => d.created + d.closed), 1);

    const handleExport = async (format: 'pdf' | 'html') => {
        setIsExporting(true);
        const html = `<div style="font-family:Inter,sans-serif;padding:40px;color:#2D2D2D">
            <h1 style="color:#D04A02;border-bottom:3px solid #D04A02;padding-bottom:16px">Automation &amp; SOAR Report</h1>
            <p>Period: Last ${days} days · Generated: ${new Date().toLocaleString()}</p>
            <h2>Playbook Performance</h2>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#F7F7F7"><th style="padding:10px;border:1px solid #E5E5E5;text-align:left">Playbook</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Runs</th><th style="padding:10px;border:1px solid #E5E5E5">Success</th>
                <th style="padding:10px;border:1px solid #E5E5E5">Failed</th><th style="padding:10px;border:1px solid #E5E5E5">Rate</th></tr>
                ${playbooks.map(p => `<tr>
                    <td style="padding:8px;border:1px solid #E5E5E5;font-family:monospace">${p.name}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${p.total_runs}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;color:#27AE60">${p.succeeded}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5;color:#C0392B">${p.failed}</td>
                    <td style="padding:8px;border:1px solid #E5E5E5">${p.success_rate}%</td>
                </tr>`).join('')}
            </table></div>`;
        try {
            const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
            const res = await axios.post(endpoint, { html, filename: `Automation_Stats_${days}d.${format}` }, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url; a.download = `Automation_Stats.${format}`; a.click(); a.remove();
        } catch (e: any) { alert(`Export failed: ${e.message}`); }
        finally { setIsExporting(false); }
    };

    const Skeleton = () => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                {[1,2,3,4].map(i => <div key={i} className="stat-tile"><div className="skeleton skeleton-title" /><div className="skeleton skeleton-text" /></div>)}
            </div>
            <div className="card"><div className="skeleton skeleton-box" style={{ height: 200 }} /></div>
        </div>
    );

    const TABS: Array<{ id: TabId; label: string; icon: any; badge?: string }> = [
        { id: 'overview',  label: 'Overview',         icon: faChartPie },
        { id: 'logicapps', label: 'Logic Apps',        icon: faServer,
          badge: logicApps ? `${logicApps.enabled_count}/${logicApps.total_count}` : undefined },
        { id: 'rules',     label: 'Automation Rules',  icon: faBolt,
          badge: autoRules ? String(autoRules.total) : undefined },
        { id: 'playbooks', label: 'Playbooks',         icon: faPlay },
        { id: 'failures',  label: 'Failures',          icon: faTriangleExclamation,
          badge: failures?.total_failures ? String(failures.total_failures) : undefined },
        { id: 'outcomes',  label: 'Outcomes',          icon: faCircleCheck },
        { id: 'soar',      label: 'SOAR Actions',      icon: faListCheck },
        { id: 'ai',        label: 'AI Report',          icon: faRobot },
    ];

    return (
        <div>
            {/* ── Header ── */}
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faWandMagicSparkles} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Automation &amp; SOAR
                        </div>
                        <div className="page-subtitle">Logic app inventory, playbook executions, incident classifications, and automation rule outcomes</div>
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

                        {/* ── KPI Row ── */}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--brand)' }}>
                                <div className="stat-tile-label">Playbook Runs</div>
                                <div className="stat-tile-value">{(overview?.playbook_runs ?? 0).toLocaleString()}</div>
                                <div className="text-xs text-muted">{overview?.playbook_failed} failed</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: `3px solid ${(overview?.success_rate ?? 0) > 90 ? 'var(--low)' : 'var(--high)'}` }}>
                                <div className="stat-tile-label">Playbook Success Rate</div>
                                <div className="stat-tile-value" style={{ color: (overview?.success_rate ?? 0) > 90 ? 'var(--low)' : 'var(--high)' }}>
                                    {overview?.success_rate ?? 0}%
                                </div>
                                <div className="text-xs text-muted">{overview?.playbook_success} succeeded</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--low)' }}>
                                <div className="stat-tile-label">True Positives</div>
                                <div className="stat-tile-value" style={{ color: 'var(--low)' }}>{overview?.true_positive ?? 0}</div>
                                <div className="text-xs text-muted">of {overview?.incident_total ?? 0} total incidents</div>
                            </div>
                            <div className="stat-tile" style={{ borderTop: '3px solid var(--critical)' }}>
                                <div className="stat-tile-label">False Positives</div>
                                <div className="stat-tile-value" style={{ color: 'var(--critical)' }}>{overview?.false_positive ?? 0}</div>
                                <div className="text-xs text-muted">Tuning opportunities</div>
                            </div>
                        </div>

                        {/* ── Tabs ── */}
                        <div className="tabs" style={{ marginBottom: 0 }}>
                            {TABS.map(t => (
                                <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                                    <FontAwesomeIcon icon={t.icon} style={{ marginRight: 8 }} />{t.label}
                                    {t.badge !== undefined && (
                                        <span className="badge badge-muted" style={{ marginLeft: 7, fontSize: 10, padding: '1px 6px' }}>{t.badge}</span>
                                    )}
                                </button>
                            ))}
                        </div>

                        {/* ── Overview ── */}
                        {tab === 'overview' && (
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faChartPie} className="card-title-icon" />
                                        Incident Classification
                                    </div>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                                        {classifications.map(c => {
                                            const pct = totalClass > 0 ? (c.count / totalClass) * 100 : 0;
                                            const color = CLASS_COLORS[c.label] || '#BDC3C7';
                                            return (
                                                <div key={c.label}>
                                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                                                        <span style={{ fontWeight: 600, color }}>{c.label}</span>
                                                        <span style={{ color: 'var(--text-muted)' }}>{c.count} ({pct.toFixed(1)}%)</span>
                                                    </div>
                                                    <div style={{ height: 10, background: '#f5f5f5', borderRadius: 5 }}>
                                                        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 5, transition: 'width 0.5s ease' }} />
                                                    </div>
                                                </div>
                                            );
                                        })}
                                        {classifications.length === 0 && <div className="text-muted" style={{ textAlign: 'center', padding: 20 }}>No classification data</div>}
                                    </div>
                                </div>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faListCheck} className="card-title-icon" />
                                        Daily Created vs Closed
                                    </div>
                                    {dailyTrend.length === 0 ? (
                                        <div className="empty-state"><div className="empty-state-text">No trend data</div></div>
                                    ) : (
                                        <div>
                                            <div style={{ display: 'flex', gap: 16, marginBottom: 12 }}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                                    <div style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--brand)' }} />Created
                                                </div>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                                    <div style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--low)' }} />Closed
                                                </div>
                                            </div>
                                            <div style={{ height: 160, display: 'flex', alignItems: 'flex-end', gap: 3, paddingBottom: 6 }}>
                                                {dailyTrend.slice(-20).map((d, i) => (
                                                    <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2, alignItems: 'center', height: '100%', justifyContent: 'flex-end' }}
                                                        title={`${d.date} — Created: ${d.created}, Closed: ${d.closed}`}>
                                                        <div style={{ width: '100%', background: 'var(--low)', height: `${(d.closed / maxTrend) * 80}%`, borderRadius: '2px 2px 0 0', opacity: 0.8 }} />
                                                        <div style={{ width: '100%', background: 'var(--brand)', height: `${(d.created / maxTrend) * 80}%`, borderRadius: '2px 2px 0 0', opacity: 0.8 }} />
                                                    </div>
                                                ))}
                                            </div>
                                            <div style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center', marginTop: 4 }}>
                                                {dailyTrend[0]?.date} → {dailyTrend[dailyTrend.length - 1]?.date}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* ── Logic Apps ── */}
                        {tab === 'logicapps' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                {logicApps?.mgmt_error && (
                                    <div style={{ padding: '10px 14px', background: 'rgba(230,126,34,0.07)', border: '1px solid rgba(230,126,34,0.3)', borderRadius: 8, fontSize: 12, color: 'var(--high)' }}>
                                        <FontAwesomeIcon icon={faTriangleExclamation} style={{ marginRight: 8 }} />
                                        Management API unavailable: {logicApps.mgmt_error} — showing run history only
                                    </div>
                                )}
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 14 }}>
                                    {[
                                        { label: 'Total Logic Apps',   value: logicApps?.total_count ?? '—',   color: 'var(--text-primary)' },
                                        { label: 'Enabled',            value: logicApps?.enabled_count ?? '—',  color: 'var(--low)' },
                                        { label: 'Disabled / Stopped', value: logicApps?.disabled_count ?? '—', color: logicApps?.disabled_count ? 'var(--high)' : 'var(--text-muted)' },
                                    ].map(k => (
                                        <div key={k.label} className="stat-tile">
                                            <div className="stat-tile-label">{k.label}</div>
                                            <div className="stat-tile-value" style={{ color: k.color }}>{String(k.value)}</div>
                                        </div>
                                    ))}
                                </div>
                                <div className="card" style={{ padding: 0 }}>
                                    <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}>
                                        <div className="card-title" style={{ margin: 0 }}>
                                            <FontAwesomeIcon icon={faServer} className="card-title-icon" />
                                            Logic App Inventory
                                        </div>
                                    </div>
                                    {(!logicApps?.logic_apps?.length) ? (
                                        <div className="empty-state" style={{ padding: 60 }}>
                                            <div className="empty-state-icon"><FontAwesomeIcon icon={faServer} style={{ opacity: 0.3 }} /></div>
                                            <div className="empty-state-text">No logic apps found or Management API access not available</div>
                                        </div>
                                    ) : (
                                        <div className="data-table-wrap">
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th>Name</th>
                                                        <th style={{ width: 100 }}>State</th>
                                                        <th style={{ width: 110 }}>Trigger</th>
                                                        <th style={{ width: 80 }}>Runs (30d)</th>
                                                        <th style={{ width: 80 }}>Success</th>
                                                        <th style={{ width: 70 }}>Failed</th>
                                                        <th style={{ width: 80 }}>Rate</th>
                                                        <th style={{ width: 130 }}>Last Run</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {logicApps.logic_apps.map(app => (
                                                        <tr key={app.name}>
                                                            <td style={{ fontWeight: 600, fontSize: 12 }}>{app.name}</td>
                                                            <td>
                                                                <span className={`badge ${app.state === 'Enabled' ? 'badge-low' : app.state === 'Disabled' ? 'badge-critical' : 'badge-medium'}`} style={{ fontSize: 10 }}>
                                                                    <FontAwesomeIcon icon={app.state === 'Enabled' ? faCheck : faXmark} style={{ marginRight: 4, fontSize: 9 }} />
                                                                    {app.state}
                                                                </span>
                                                            </td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{app.trigger_type || '—'}</td>
                                                            <td style={{ fontWeight: 700 }}>{app.total_runs > 0 ? app.total_runs : <span style={{ color: 'var(--text-muted)' }}>0</span>}</td>
                                                            <td style={{ color: 'var(--low)', fontWeight: 600 }}>{app.succeeded || '—'}</td>
                                                            <td style={{ color: app.failed > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>{app.failed > 0 ? app.failed : '—'}</td>
                                                            <td>
                                                                {app.success_rate !== null ? (
                                                                    <span className={`badge ${app.success_rate >= 95 ? 'badge-low' : app.success_rate >= 80 ? 'badge-medium' : 'badge-critical'}`} style={{ fontSize: 10 }}>
                                                                        {app.success_rate}%
                                                                    </span>
                                                                ) : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>No runs</span>}
                                                            </td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                                {app.last_run ? new Date(app.last_run).toLocaleDateString() : '—'}
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* ── Automation Rules ── */}
                        {tab === 'rules' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 14 }}>
                                    {[
                                        { label: 'Total Rules',          value: autoRules?.total ?? '—',          color: 'var(--text-primary)' },
                                        { label: 'Enabled',              value: autoRules?.enabled_count ?? '—',  color: 'var(--low)' },
                                        { label: 'Disabled',             value: autoRules?.disabled_count ?? '—', color: autoRules?.disabled_count ? 'var(--high)' : 'var(--text-muted)' },
                                        { label: 'Trigger Playbooks',    value: autoRules?.playbook_rules ?? '—', color: 'var(--brand)' },
                                    ].map(k => (
                                        <div key={k.label} className="stat-tile">
                                            <div className="stat-tile-label">{k.label}</div>
                                            <div className="stat-tile-value" style={{ color: k.color }}>{String(k.value)}</div>
                                        </div>
                                    ))}
                                </div>
                                <div className="card" style={{ padding: 0 }}>
                                    <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}>
                                        <div className="card-title" style={{ margin: 0 }}>
                                            <FontAwesomeIcon icon={faBolt} className="card-title-icon" style={{ color: 'var(--brand)' }} />
                                            Sentinel Automation Rules
                                        </div>
                                    </div>
                                    {(!autoRules?.rules?.length) ? (
                                        <div className="empty-state" style={{ padding: 60 }}>
                                            <div className="empty-state-icon"><FontAwesomeIcon icon={faBolt} style={{ opacity: 0.3 }} /></div>
                                            <div className="empty-state-text">No automation rules found</div>
                                        </div>
                                    ) : (
                                        <div className="data-table-wrap">
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th>Rule Name</th>
                                                        <th style={{ width: 80 }}>Status</th>
                                                        <th style={{ width: 60 }}>Order</th>
                                                        <th style={{ width: 110 }}>Trigger</th>
                                                        <th>Actions</th>
                                                        <th style={{ width: 130 }}>Last Modified</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {autoRules.rules.map(rule => (
                                                        <tr key={rule.id}>
                                                            <td style={{ fontWeight: 600, fontSize: 12 }}>{rule.display_name || rule.id}</td>
                                                            <td>
                                                                <span className={`badge ${rule.enabled ? 'badge-low' : 'badge-critical'}`} style={{ fontSize: 10 }}>
                                                                    <FontAwesomeIcon icon={rule.enabled ? faCheck : faXmark} style={{ marginRight: 4, fontSize: 9 }} />
                                                                    {rule.enabled ? 'Enabled' : 'Disabled'}
                                                                </span>
                                                            </td>
                                                            <td style={{ fontWeight: 700, fontSize: 12 }}>{rule.order}</td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                                {rule.trigger_when || rule.trigger_kind || '—'}
                                                            </td>
                                                            <td>
                                                                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                                                                    {rule.actions.map((a, i) => (
                                                                        <span key={i} className={`badge ${a.type === 'RunPlaybook' ? 'badge-medium' : 'badge-muted'}`} style={{ fontSize: 10 }}>
                                                                            {a.type === 'RunPlaybook' ? `▶ ${(a.playbook || '').split('/').pop() || 'Playbook'}` : a.type}
                                                                        </span>
                                                                    ))}
                                                                </div>
                                                            </td>
                                                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                                {rule.last_modified ? new Date(rule.last_modified).toLocaleDateString() : '—'}
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* ── Playbooks ── */}
                        {tab === 'playbooks' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faPlay} className="card-title-icon" style={{ color: 'var(--brand)' }} />
                                        Playbook Execution Statistics
                                    </div>
                                </div>
                                {playbooks.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}>
                                        <div className="empty-state-icon"><FontAwesomeIcon icon={faPlay} style={{ opacity: 0.3 }} /></div>
                                        <div className="empty-state-text">No Logic App / playbook activity found in AzureActivity</div>
                                    </div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Playbook Name</th>
                                                    <th style={{ width: 90 }}>Runs</th>
                                                    <th style={{ width: 80 }}>Success</th>
                                                    <th style={{ width: 70 }}>Failed</th>
                                                    <th style={{ width: 80 }}>Rate</th>
                                                    <th>Performance</th>
                                                    <th style={{ width: 150 }}>Last Run</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {playbooks.map(p => (
                                                    <tr key={p.name}>
                                                        <td style={{ fontWeight: 600, fontSize: 12 }}>{p.name}</td>
                                                        <td style={{ fontWeight: 700 }}>{p.total_runs}</td>
                                                        <td style={{ color: 'var(--low)', fontWeight: 600 }}>{p.succeeded}</td>
                                                        <td style={{ color: p.failed > 0 ? 'var(--critical)' : 'var(--text-muted)', fontWeight: 600 }}>{p.failed}</td>
                                                        <td>
                                                            <span className={`badge ${p.success_rate >= 95 ? 'badge-low' : p.success_rate >= 80 ? 'badge-medium' : 'badge-critical'}`}>
                                                                {p.success_rate}%
                                                            </span>
                                                        </td>
                                                        <td style={{ width: 150 }}>
                                                            <div style={{ height: 8, background: '#f0f0f0', borderRadius: 4, overflow: 'hidden' }}>
                                                                <div style={{ width: `${(p.total_runs / maxRuns) * 100}%`, height: '100%', background: p.success_rate >= 90 ? 'var(--low)' : 'var(--high)', borderRadius: 4 }} />
                                                            </div>
                                                        </td>
                                                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                            {p.last_run ? new Date(p.last_run).toLocaleDateString() : '—'}
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* ── Failures ── */}
                        {tab === 'failures' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                                    {/* Top failing playbooks */}
                                    <div className="card">
                                        <div className="card-title">
                                            <FontAwesomeIcon icon={faTriangleExclamation} className="card-title-icon" style={{ color: 'var(--critical)' }} />
                                            Top Failing Playbooks
                                        </div>
                                        {!failures?.by_playbook?.length ? (
                                            <div className="empty-state"><div className="empty-state-text">No failures recorded</div></div>
                                        ) : (
                                            <div className="data-table-wrap">
                                                <table className="data-table">
                                                    <thead><tr><th>Playbook</th><th style={{ width: 100 }}>Failures</th><th style={{ width: 120 }}>Last Failure</th></tr></thead>
                                                    <tbody>
                                                        {failures.by_playbook.map(f => (
                                                            <tr key={f.name}>
                                                                <td style={{ fontWeight: 600, fontSize: 12 }}>{f.name}</td>
                                                                <td>
                                                                    <span className="badge badge-critical" style={{ fontSize: 11 }}>{f.failed_runs}</span>
                                                                </td>
                                                                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                                    {f.last_failure ? new Date(f.last_failure).toLocaleDateString() : '—'}
                                                                </td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            </div>
                                        )}
                                    </div>

                                    {/* Failure reasons */}
                                    <div className="card">
                                        <div className="card-title">
                                            <FontAwesomeIcon icon={faCircleXmark} className="card-title-icon" style={{ color: 'var(--high)' }} />
                                            Failure Reason Patterns
                                        </div>
                                        {!failures?.failure_reasons?.length ? (
                                            <div className="empty-state">
                                                <div className="empty-state-text">No structured error data available</div>
                                                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>AzureDiagnostics requires Logic Apps diagnostic settings to be enabled</div>
                                            </div>
                                        ) : (
                                            <div className="data-table-wrap">
                                                <table className="data-table">
                                                    <thead><tr><th>Error Code</th><th>Message</th><th style={{ width: 60 }}>Count</th></tr></thead>
                                                    <tbody>
                                                        {failures.failure_reasons.map((r, i) => (
                                                            <tr key={i}>
                                                                <td><code style={{ fontSize: 11 }}>{r.error_code || '—'}</code></td>
                                                                <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{r.error_message || '—'}</td>
                                                                <td style={{ fontWeight: 700 }}>{r.count}</td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Daily failure trend */}
                                {failures?.daily_trend?.length ? (
                                    <div className="card">
                                        <div className="card-title">
                                            <FontAwesomeIcon icon={faChartPie} className="card-title-icon" />
                                            Daily Run vs Failure Trend
                                        </div>
                                        <div style={{ display: 'flex', gap: 16, marginBottom: 12 }}>
                                            {[
                                                { color: 'var(--low)', label: 'Succeeded' },
                                                { color: 'var(--critical)', label: 'Failed' },
                                            ].map(l => (
                                                <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                                                    <div style={{ width: 10, height: 10, borderRadius: 2, background: l.color }} />{l.label}
                                                </div>
                                            ))}
                                        </div>
                                        <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 3 }}>
                                            {failures.daily_trend.slice(-30).map((d, i) => {
                                                const maxVal = Math.max(...failures!.daily_trend.map(x => x.total), 1);
                                                return (
                                                    <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 1, height: '100%', justifyContent: 'flex-end' }}
                                                        title={`${d.date} — Total: ${d.total}, Failed: ${d.failed}`}>
                                                        <div style={{ width: '100%', background: 'var(--critical)', height: `${(d.failed / maxVal) * 80}%`, borderRadius: '2px 2px 0 0', opacity: 0.85 }} />
                                                        <div style={{ width: '100%', background: 'var(--low)', height: `${(d.succeeded / maxVal) * 80}%`, borderRadius: '2px 2px 0 0', opacity: 0.7 }} />
                                                    </div>
                                                );
                                            })}
                                        </div>
                                        <div style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center', marginTop: 4 }}>
                                            {failures.daily_trend[0]?.date} → {failures.daily_trend[failures.daily_trend.length - 1]?.date}
                                        </div>
                                    </div>
                                ) : null}
                            </div>
                        )}

                        {/* ── Outcomes ── */}
                        {tab === 'outcomes' && (
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faCircleCheck} className="card-title-icon" style={{ color: 'var(--low)' }} />
                                        Classification Breakdown
                                    </div>
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead><tr><th>Classification</th><th>Count</th><th>Share</th></tr></thead>
                                            <tbody>
                                                {classifications.map(c => {
                                                    const pct = totalClass > 0 ? ((c.count / totalClass) * 100).toFixed(1) : '0.0';
                                                    const color = CLASS_COLORS[c.label] || '#BDC3C7';
                                                    return (
                                                        <tr key={c.label}>
                                                            <td style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                                <div style={{ width: 10, height: 10, borderRadius: 2, background: color, flexShrink: 0 }} />
                                                                <span style={{ fontWeight: 600 }}>{c.label}</span>
                                                            </td>
                                                            <td style={{ fontWeight: 700 }}>{c.count.toLocaleString()}</td>
                                                            <td style={{ color: 'var(--text-muted)' }}>{pct}%</td>
                                                        </tr>
                                                    );
                                                })}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <div className="card">
                                    <div className="card-title">
                                        <FontAwesomeIcon icon={faCircleXmark} className="card-title-icon" style={{ color: 'var(--high)' }} />
                                        Tuning Opportunities
                                    </div>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                        {[
                                            { label: 'True Positive Rate', val: totalClass > 0 ? ((overview?.true_positive ?? 0) / totalClass * 100).toFixed(1) : '0.0', target: '> 70%', color: 'var(--low)' },
                                            { label: 'False Positive Rate', val: totalClass > 0 ? ((overview?.false_positive ?? 0) / totalClass * 100).toFixed(1) : '0.0', target: '< 20%', color: 'var(--critical)' },
                                            { label: 'Playbook Success Rate', val: String(overview?.success_rate ?? 0), target: '> 95%', color: (overview?.success_rate ?? 0) >= 95 ? 'var(--low)' : 'var(--high)' },
                                        ].map(item => (
                                            <div key={item.label} style={{ padding: '12px 14px', background: 'var(--bg-base)', borderRadius: 8, border: '1px solid var(--border-color)' }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                                                    <span style={{ fontSize: 12, fontWeight: 600 }}>{item.label}</span>
                                                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Target: {item.target}</span>
                                                </div>
                                                <div style={{ fontSize: 22, fontWeight: 800, color: item.color }}>{item.val}%</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* ── SOAR ── */}
                        {tab === 'soar' && (
                            <div className="card" style={{ padding: 0 }}>
                                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
                                    <div className="card-title" style={{ margin: 0 }}>
                                        <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" style={{ color: 'var(--brand)' }} />
                                        SOAR Automation Outcomes by Status
                                    </div>
                                </div>
                                {soarActions.length === 0 ? (
                                    <div className="empty-state" style={{ padding: 60 }}>
                                        <div className="empty-state-text">No SOAR action data available</div>
                                    </div>
                                ) : (
                                    <div className="data-table-wrap">
                                        <table className="data-table">
                                            <thead>
                                                <tr>
                                                    <th>Incident Status</th>
                                                    <th style={{ width: 90 }}>Total</th>
                                                    <th style={{ width: 100 }}>With Owner</th>
                                                    <th style={{ width: 110 }}>Unassigned</th>
                                                    <th style={{ width: 100 }}>High Sev</th>
                                                    <th style={{ width: 110 }}>Auto-Labeled</th>
                                                    <th>Assignment Rate</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {soarActions.map(r => {
                                                    const assignRate = r.total > 0 ? Math.round((r.with_owner / r.total) * 100) : 0;
                                                    return (
                                                        <tr key={r.status}>
                                                            <td style={{ fontWeight: 600 }}>{r.status}</td>
                                                            <td style={{ fontWeight: 700 }}>{r.total.toLocaleString()}</td>
                                                            <td style={{ color: 'var(--low)', fontWeight: 600 }}>{r.with_owner.toLocaleString()}</td>
                                                            <td style={{ color: r.without_owner > 0 ? 'var(--high)' : 'var(--text-muted)' }}>{r.without_owner.toLocaleString()}</td>
                                                            <td style={{ color: r.high_severity > 0 ? 'var(--critical)' : 'var(--text-muted)', fontWeight: 600 }}>{r.high_severity.toLocaleString()}</td>
                                                            <td>{r.auto_labeled.toLocaleString()}</td>
                                                            <td style={{ width: 180 }}>
                                                                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                                                    <div style={{ flex: 1, height: 8, background: '#f0f0f0', borderRadius: 4 }}>
                                                                        <div style={{ width: `${assignRate}%`, height: '100%', background: assignRate >= 80 ? 'var(--low)' : 'var(--high)', borderRadius: 4 }} />
                                                                    </div>
                                                                    <span style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 32 }}>{assignRate}%</span>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    );
                                                })}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* ── AI Report ── */}
                        {tab === 'ai' && <AiReportPanel days={days} />}

                    </div>
                )}
            </div>
        </div>
    );
}
