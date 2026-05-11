import { useState, useEffect, useMemo } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { ReportLogPanel, type LogStep } from '../components/ReportLogPanel';
import {
    faBookOpen, faTableCells, faList, faClockRotateLeft,
    faCircleCheck, faCircleXmark, faTriangleExclamation,
    faMagnifyingGlass, faCheck, faXmark, faArrowRotateRight,
    faLock, faArrowUpRightFromSquare, faFileCode,
    faRobot, faFilePdf, faBolt,
} from '@fortawesome/free-solid-svg-icons';

// ── Types ─────────────────────────────────────────────────────────────────────
interface Workbook {
    id: string; name: string; description: string; category: string;
    kind: string; version: string; template_id: string;
    last_modified: string; days_since_modified: number | null;
    stale: boolean; location: string;
}
interface CoverageEntry {
    category: string; priority: 'Critical' | 'High' | 'Medium' | 'Low';
    covered: boolean; count: number; stale_count: number; remediation: string;
    workbooks: Array<{ name: string; last_modified: string; days_since_modified: number | null; stale: boolean; kind: string }>;
}
interface CoverageData {
    summary: {
        total_workbooks: number; total_categories: number;
        covered_expected: number; total_expected: number;
        coverage_pct: number; stale_count: number; recent_count: number; shared_count: number;
    };
    coverage_matrix: CoverageEntry[];
    extra_categories: Array<{ category: string; count: number; workbooks: string[] }>;
    by_category: Record<string, Array<{ name: string; stale: boolean; last_modified: string }>>;
    all_workbooks: Workbook[];
    error?: string;
}
interface ActivityRow {
    operation: string; resource: string; status: string;
    caller: string; count: number; last_seen: string;
}
type TabId = 'coverage' | 'workbooks' | 'activity' | 'report';

// ── Markdown → HTML (proper line-by-line parser) ──────────────────────────────
function mdToHtml(md: string, cssVars = true): string {
    const inline = (t: string) => t
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/`(.+?)`/g, cssVars
            ? '<code style="background:var(--bg-surface);padding:1px 5px;border-radius:3px;font-size:11px;font-family:monospace">$1</code>'
            : '<code>$1</code>');

    const h2Style = cssVars
        ? 'color:var(--brand);margin:22px 0 10px;font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;border-bottom:2px solid var(--brand);padding-bottom:5px'
        : 'color:#D04A02;margin:22px 0 10px;font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;border-bottom:2px solid #D04A02;padding-bottom:5px';
    const h3Style = cssVars
        ? 'margin:16px 0 6px;font-size:13px;font-weight:700;color:var(--text-primary)'
        : 'margin:16px 0 6px;font-size:13px;font-weight:700;color:#1e293b';
    const tableStyle = 'border-collapse:collapse;width:100%;font-size:12px;margin:12px 0';
    const thStyle = cssVars
        ? 'padding:7px 12px;border:1px solid var(--border);background:var(--bg-surface);font-weight:700;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.04em'
        : 'padding:7px 12px;border:1px solid #e2e8f0;background:#f1f5f9;font-weight:700;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.04em';
    const tdStyle = cssVars
        ? 'padding:7px 12px;border:1px solid var(--border);vertical-align:top'
        : 'padding:7px 12px;border:1px solid #e2e8f0;vertical-align:top';
    const bqStyle = cssVars
        ? 'border-left:3px solid var(--brand);margin:10px 0;padding:8px 14px;background:var(--bg-surface);font-style:italic;font-size:12px'
        : 'border-left:3px solid #D04A02;margin:10px 0;padding:8px 14px;background:#f8fafc;font-style:italic;font-size:12px';

    const lines = md.split('\n');
    const out: string[] = [];
    let i = 0;

    while (i < lines.length) {
        const raw = lines[i];
        const line = raw.trimEnd();

        // Fenced code block
        if (line.startsWith('```')) {
            i++;
            const codeLines: string[] = [];
            while (i < lines.length && !lines[i].startsWith('```')) {
                codeLines.push(lines[i].replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'));
                i++;
            }
            const codeStyle = cssVars
                ? 'background:var(--bg-surface);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-family:monospace;font-size:12px;overflow-x:auto;margin:8px 0'
                : 'background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:10px 14px;font-family:monospace;font-size:12px;overflow-x:auto;margin:8px 0';
            out.push(`<pre style="${codeStyle}"><code>${codeLines.join('\n')}</code></pre>`);
            i++; continue;
        }

        // H1
        if (/^# /.test(line)) {
            const h1Style = cssVars
                ? 'font-size:20px;font-weight:800;color:var(--text-primary);margin:0 0 6px'
                : 'font-size:20px;font-weight:800;color:#0f172a;margin:0 0 6px';
            out.push(`<h1 style="${h1Style}">${inline(line.slice(2))}</h1>`);
            i++; continue;
        }
        // H2
        if (/^## /.test(line)) {
            out.push(`<h2 style="${h2Style}">${inline(line.slice(3))}</h2>`);
            i++; continue;
        }
        // H3
        if (/^### /.test(line)) {
            out.push(`<h3 style="${h3Style}">${inline(line.slice(4))}</h3>`);
            i++; continue;
        }
        // H4
        if (/^#### /.test(line)) {
            out.push(`<h4 style="margin:12px 0 4px;font-size:12px;font-weight:700">${inline(line.slice(5))}</h4>`);
            i++; continue;
        }
        // HR
        if (/^---+$/.test(line.trim()) || /^\*\*\*+$/.test(line.trim())) {
            const hrStyle = cssVars ? 'border:none;border-top:1px solid var(--border);margin:16px 0' : 'border:none;border-top:1px solid #e2e8f0;margin:16px 0';
            out.push(`<hr style="${hrStyle}">`);
            i++; continue;
        }
        // Table
        if (line.trim().startsWith('|')) {
            const tableLines: string[] = [];
            while (i < lines.length && lines[i].trim().startsWith('|')) {
                tableLines.push(lines[i]);
                i++;
            }
            let tHtml = `<table style="${tableStyle}">`;
            let headerDone = false;
            for (const tl of tableLines) {
                const isSep = tl.split('|').filter(Boolean).every(c => /^[\s\-:]+$/.test(c));
                if (isSep) continue;
                const cells = tl.split('|').filter(Boolean).map(c => c.trim());
                if (!headerDone) {
                    tHtml += `<thead><tr>${cells.map(c => `<th style="${thStyle}">${inline(c)}</th>`).join('')}</tr></thead><tbody>`;
                    headerDone = true;
                } else {
                    tHtml += `<tr>${cells.map(c => `<td style="${tdStyle}">${inline(c)}</td>`).join('')}</tr>`;
                }
            }
            tHtml += headerDone ? '</tbody></table>' : '</table>';
            out.push(tHtml);
            continue;
        }
        // Unordered list
        if (/^[-*] /.test(line)) {
            const ulStyle = cssVars ? 'padding-left:22px;margin:8px 0' : 'padding-left:22px;margin:8px 0';
            const liStyle = 'margin:4px 0;font-size:13px;line-height:1.6';
            let ulHtml = `<ul style="${ulStyle}">`;
            while (i < lines.length && /^[-*] /.test(lines[i])) {
                ulHtml += `<li style="${liStyle}">${inline(lines[i].replace(/^[-*] /, ''))}</li>`;
                i++;
            }
            ulHtml += '</ul>';
            out.push(ulHtml);
            continue;
        }
        // Ordered list
        if (/^\d+\. /.test(line)) {
            const olStyle = 'padding-left:22px;margin:8px 0';
            const liStyle = 'margin:4px 0;font-size:13px;line-height:1.6';
            let olHtml = `<ol style="${olStyle}">`;
            while (i < lines.length && /^\d+\. /.test(lines[i])) {
                olHtml += `<li style="${liStyle}">${inline(lines[i].replace(/^\d+\. /, ''))}</li>`;
                i++;
            }
            olHtml += '</ol>';
            out.push(olHtml);
            continue;
        }
        // Blockquote
        if (/^> /.test(line)) {
            out.push(`<blockquote style="${bqStyle}">${inline(line.slice(2))}</blockquote>`);
            i++; continue;
        }
        // Empty line
        if (line.trim() === '') {
            out.push('<div style="height:6px"></div>');
            i++; continue;
        }
        // Regular paragraph
        out.push(`<p style="margin:5px 0;font-size:13px;line-height:1.7">${inline(line)}</p>`);
        i++;
    }

    return out.join('\n');
}

// ── Export HTML builder ───────────────────────────────────────────────────────
function buildExportHtml(title: string, analysis: string, days: number, generatedAt: string): string {
    const body = mdToHtml(analysis, false);
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
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
    <h1>${title}</h1>
    <p class="meta">Period: Last ${days} days &nbsp;·&nbsp; Generated: ${new Date(generatedAt).toLocaleString()}</p>
    <span class="confidential">Confidential — Internal Use Only</span>
  </div>
  <div class="report-body">
    ${body}
  </div>
  <div class="footer">
    <span>Sentinel Vigil · Microsoft Sentinel</span>
    <span>${title} · ${new Date(generatedAt).toLocaleString()}</span>
  </div>
</div>
</body>
</html>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const PRIORITY_COLOR: Record<string, string> = {
    Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)', Low: 'var(--low)',
};
const PRIORITY_BG: Record<string, string> = {
    Critical: 'rgba(192,57,43,0.07)', High: 'rgba(230,126,34,0.07)',
    Medium: 'rgba(212,172,13,0.07)', Low: 'rgba(39,174,96,0.07)',
};

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

function opLabel(raw: string): string {
    return raw.replace('MICROSOFT.INSIGHTS/WORKBOOKS/', '').replace(/\//g, ' › ')
        .toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
}

// ── Coverage Score Ring ───────────────────────────────────────────────────────
function ScoreRing({ pct }: { pct: number }) {
    const r = 46;
    const circ = 2 * Math.PI * r;
    const dash = (pct / 100) * circ;
    const color = pct >= 75 ? 'var(--low)' : pct >= 50 ? 'var(--medium)' : pct >= 30 ? 'var(--high)' : 'var(--critical)';
    return (
        <div style={{ position: 'relative', width: 112, height: 112, flexShrink: 0 }}>
            <svg width="112" height="112" style={{ transform: 'rotate(-90deg)' }}>
                <circle cx="56" cy="56" r={r} fill="none" stroke="var(--border)" strokeWidth="10" />
                <circle cx="56" cy="56" r={r} fill="none" stroke={color} strokeWidth="10"
                    strokeDasharray={`${dash} ${circ - dash}`}
                    strokeLinecap="round"
                    style={{ transition: 'stroke-dasharray 0.8s ease' }}
                />
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <div className="card-metric-value" style={{ fontSize: 22, color, lineHeight: 1 }}>{pct}%</div>
                <div className="text-muted" style={{ fontSize: 9, marginTop: 2, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Coverage</div>
            </div>
        </div>
    );
}

// ── AI Report Tab Content ─────────────────────────────────────────────────────
interface TokenUsage { input_tokens: number; output_tokens: number; model: string; }

const WORKBOOK_LOG_STEPS: LogStep[] = [
    { level: 'info', msg: 'Connecting to Sentinel workspace…',            delay: 400 },
    { level: 'info', msg: 'Enumerating workbook inventory…',              delay: 2500 },
    { level: 'info', msg: 'Fetching workbook activity & usage data…',     delay: 5000 },
    { level: 'info', msg: 'Analysing coverage matrix…',                   delay: 7500 },
    { level: 'info', msg: 'Checking for stale & orphaned workbooks…',     delay: 10500 },
    { level: 'ai',   msg: 'Running LLM analysis with Claude…',            delay: 13500 },
    { level: 'ai',   msg: 'Generating coverage recommendations…',         delay: 18000 },
];

function AiReportTab() {
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState<boolean | null>(null);
    const [report, setReport]   = useState<{ llm_analysis: string; generated_at: string; token_usage?: TokenUsage } | null>(null);
    const [error, setError]     = useState<string | null>(null);
    const [model, setModel]     = useState('claude-sonnet-4-6');

    const generate = async () => {
        setLoading(true); setError(null); setReport(null); setSuccess(null);
        try {
            const res = await axios.get(`/api/workbooks/report?days=30&model=${model}`, { timeout: 0 });
            setReport(res.data);
            setSuccess(true);
        } catch (e: any) {
            setError(e.response?.data?.detail || e.message || 'Report generation failed');
            setSuccess(false);
        } finally { setLoading(false); }
    };

    const doExport = async (format: 'html' | 'pdf') => {
        if (!report) return;
        const html = buildExportHtml('Workbook Coverage Report', report.llm_analysis, 30, report.generated_at);
        const endpoint = format === 'pdf' ? '/api/reports/export-pdf' : '/api/reports/export-html';
        try {
            const res = await axios.post(endpoint, { html, filename: `Workbook_Coverage_Report.${format}` }, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const a = document.createElement('a'); a.href = url;
            a.download = `Workbook_Coverage_Report.${format}`; a.click(); a.remove();
        } catch (e: any) { alert(`Export failed: ${e.message}`); }
    };

    if (!report && !loading) {
        return (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '60px 0', gap: 16 }}>
                <FontAwesomeIcon icon={faRobot} style={{ fontSize: 48, color: 'var(--brand)', opacity: 0.7 }} />
                <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>AI Workbook Coverage Report</div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', textAlign: 'center', maxWidth: 420, lineHeight: 1.6 }}>
                    Click Generate to run an LLM-powered analysis across your entire workbook inventory —
                    gap analysis, stale workbook risk, health summary, and specific deployment recommendations.
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <select
                        value={model}
                        onChange={e => setModel(e.target.value)}
                        className="form-select"
                        style={{ fontSize: 12, padding: '4px 8px' }}
                    >
                        <option value="claude-sonnet-4-6">Sonnet 4.6</option>
                        <option value="claude-haiku-4-5">Haiku 4.5</option>

                    </select>
                    <button className="btn btn-primary" onClick={generate}>
                        <FontAwesomeIcon icon={faRobot} style={{ marginRight: 8 }} />
                        Generate AI Report
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div>
            {/* Action bar */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, gap: 10, flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {report && (
                        <>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                Generated {new Date(report.generated_at).toLocaleString()}
                            </div>
                            {report.token_usage && (
                                <span style={{
                                    display: 'inline-flex', alignItems: 'center', gap: 5,
                                    fontSize: 10, fontFamily: 'monospace',
                                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                                    borderRadius: 6, padding: '2px 8px', color: 'var(--text-muted)',
                                    width: 'fit-content',
                                }}>
                                    <FontAwesomeIcon icon={faBolt} style={{ color: 'var(--warning)', fontSize: 9 }} />
                                    <span style={{ color: 'var(--info)' }}>{report.token_usage.input_tokens.toLocaleString()}</span>
                                    <span>in</span>
                                    <span style={{ opacity: 0.5 }}>→</span>
                                    <span style={{ color: '#27ae60' }}>{report.token_usage.output_tokens.toLocaleString()}</span>
                                    <span>out</span>
                                    <span style={{ opacity: 0.4 }}>·</span>
                                    <span style={{ opacity: 0.7 }}>{report.token_usage.model}</span>
                                </span>
                            )}
                        </>
                    )}
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    {report && (
                        <>
                            <button className="btn btn-sm btn-ghost" onClick={() => doExport('html')}>
                                <FontAwesomeIcon icon={faFileCode} style={{ color: 'var(--info)', marginRight: 6 }} />HTML
                            </button>
                            <button className="btn btn-sm btn-ghost" onClick={() => doExport('pdf')}>
                                <FontAwesomeIcon icon={faFilePdf} style={{ color: 'var(--critical)', marginRight: 6 }} />PDF
                            </button>
                        </>
                    )}
                    <select
                        value={model}
                        onChange={e => setModel(e.target.value)}
                        disabled={loading}
                        className="form-select"
                        style={{ fontSize: 12, padding: '4px 8px' }}
                    >
                        <option value="claude-sonnet-4-6">Sonnet 4.6</option>
                        <option value="claude-haiku-4-5">Haiku 4.5</option>

                    </select>
                    <button className="btn btn-sm btn-primary" onClick={generate} disabled={loading}>
                        <FontAwesomeIcon icon={faRobot} spin={loading} style={{ marginRight: 6 }} />
                        {loading ? 'Generating…' : 'Regenerate'}
                    </button>
                </div>
            </div>

            <ReportLogPanel steps={WORKBOOK_LOG_STEPS} loading={loading} success={success} error={error} />

            {error && (
                <div style={{ padding: '12px 16px', background: 'rgba(192,57,43,0.07)', border: '1px solid rgba(192,57,43,0.25)', borderRadius: 8, fontSize: 12, color: 'var(--critical)', marginBottom: 16 }}>
                    <FontAwesomeIcon icon={faCircleXmark} style={{ marginRight: 8 }} />{error}
                </div>
            )}

            {report && (
                <div style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    borderRadius: 12,
                    padding: '24px 28px',
                    lineHeight: 1.7,
                }}>
                    <div dangerouslySetInnerHTML={{ __html: mdToHtml(report.llm_analysis, true) }} />
                </div>
            )}
        </div>
    );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function WorkbookCoverage() {
    const [coverage, setCoverage]     = useState<CoverageData | null>(null);
    const [loading, setLoading]       = useState(true);
    const [tab, setTab]               = useState<TabId>('coverage');
    const [activity, setActivity]     = useState<ActivityRow[]>([]);
    const [actLoading, setActLoading] = useState(false);
    const [actLoaded, setActLoaded]   = useState(false);
    const [search, setSearch]         = useState('');
    const [catFilter, setCatFilter]   = useState('All');
    const [expandedCat, setExpandedCat] = useState<string | null>(null);

    const fetchCoverage = () => {
        setLoading(true);
        axios.get('/api/workbooks/coverage')
            .then(r => setCoverage(r.data))
            .catch(() => setCoverage(null))
            .finally(() => setLoading(false));
    };

    useEffect(() => { fetchCoverage(); }, []);

    useEffect(() => {
        if (tab === 'activity' && !actLoaded) {
            setActLoading(true);
            axios.get('/api/workbooks/activity')
                .then(r => setActivity(r.data.activity || []))
                .catch(() => setActivity([]))
                .finally(() => { setActLoading(false); setActLoaded(true); });
        }
    }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps

    const allWorkbooks = coverage?.all_workbooks ?? [];
    const categories   = useMemo(() => ['All', ...Object.keys(coverage?.by_category ?? {}).sort()], [coverage]);
    const filteredWorkbooks = useMemo(() => {
        const q = search.toLowerCase();
        return allWorkbooks.filter(w => {
            const matchSearch = !q || w.name.toLowerCase().includes(q) || w.category.toLowerCase().includes(q);
            const matchCat    = catFilter === 'All' || w.category === catFilter;
            return matchSearch && matchCat;
        });
    }, [allWorkbooks, search, catFilter]);

    const summary = coverage?.summary;
    const matrix  = coverage?.coverage_matrix ?? [];
    const gaps    = matrix.filter(e => !e.covered);

    const exportCoverageHTML = () => {
        if (!coverage || !summary) return;
        const esc = (s: string) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const dateStr = new Date().toLocaleString();
        const priColor: Record<string, string> = { Critical: '#c0392b', High: '#e67e22', Medium: '#d4ac0d', Low: '#27ae60' };
        const matrixRows = matrix.map(e => `
            <tr>
                <td><strong>${esc(e.category)}</strong></td>
                <td><span class="badge ${e.covered ? 'covered' : 'gap'}">${e.covered ? '✔ Covered' : '✘ Gap'}</span></td>
                <td><span style="color:${priColor[e.priority] ?? '#888'};font-weight:700">${esc(e.priority)}</span></td>
                <td style="text-align:center">${e.count}</td>
                <td style="text-align:center;color:${e.stale_count ? '#e67e22' : '#27ae60'}">${e.stale_count}</td>
                <td style="font-size:11px;color:#64748b">${e.covered ? e.workbooks.map(w => esc(w.name)).join(', ') : esc(e.remediation)}</td>
            </tr>`).join('');
        const wbRows = allWorkbooks.map(w => `
            <tr>
                <td><strong>${esc(w.name)}</strong>${w.description ? `<br/><span style="font-size:10px;color:#94a3b8">${esc(w.description.slice(0, 120))}</span>` : ''}</td>
                <td>${esc(w.category)}</td><td>${esc(w.kind)}</td>
                <td><span class="badge ${w.stale ? 'gap' : 'covered'}">${w.stale ? 'Stale' : 'Current'}</span></td>
                <td>${w.days_since_modified !== null ? `${w.days_since_modified}d ago` : '—'}</td>
            </tr>`).join('');
        const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Workbook Coverage</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:40px;color:#1e293b;background:#f8fafc;margin:0}
h1{color:#D04A02;border-bottom:3px solid #D04A02;padding-bottom:10px;font-size:22px;margin-bottom:4px}
h2{font-size:15px;color:#334155;margin:28px 0 10px;text-transform:uppercase;letter-spacing:.06em;border-left:3px solid #D04A02;padding-left:10px}
.meta{font-size:12px;color:#64748b;margin:0 0 20px}
.kpi-row{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
.kpi{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 20px;min-width:130px;text-align:center}
.kpi-val{font-size:26px;font-weight:800;color:#D04A02}
.kpi-lbl{font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;margin-top:3px}
.alert{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 16px;color:#b91c1c;font-size:13px;margin-bottom:20px}
table{border-collapse:collapse;width:100%;font-size:12px;margin-bottom:28px}
th{background:#f1f5f9;text-align:left;padding:9px 12px;border:1px solid #e2e8f0;font-weight:700;color:#475569;text-transform:uppercase;font-size:10px;letter-spacing:.04em}
td{padding:8px 12px;border:1px solid #e2e8f0;vertical-align:top;color:#1e293b}
tr:nth-child(even) td{background:#f8fafc}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700}
.covered{background:#dcfce7;color:#166534} .gap{background:#fee2e2;color:#991b1b}
.footer{margin-top:30px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px;display:flex;justify-content:space-between}
</style></head><body>
<h1>Workbook Coverage Report</h1>
<div class="meta">Generated: ${dateStr} · Coverage across ${matrix.length} security domains</div>
<div class="kpi-row">
  <div class="kpi"><div class="kpi-val">${summary.coverage_pct}%</div><div class="kpi-lbl">Coverage</div></div>
  <div class="kpi"><div class="kpi-val">${summary.total_workbooks}</div><div class="kpi-lbl">Total Workbooks</div></div>
  <div class="kpi"><div class="kpi-val">${summary.covered_expected}/${summary.total_expected}</div><div class="kpi-lbl">Domains Covered</div></div>
  <div class="kpi"><div class="kpi-val" style="color:${gaps.length ? '#c0392b' : '#27ae60'}">${gaps.length}</div><div class="kpi-lbl">Gaps</div></div>
  <div class="kpi"><div class="kpi-val" style="color:${summary.stale_count ? '#e67e22' : '#27ae60'}">${summary.stale_count}</div><div class="kpi-lbl">Stale (>90d)</div></div>
</div>
${gaps.length > 0 ? `<div class="alert">⚠️ <strong>${gaps.length} gap${gaps.length > 1 ? 's' : ''}:</strong> ${gaps.map(g => g.category).join(' · ')}</div>` : ''}
<h2>Coverage Matrix</h2>
<table><thead><tr><th>Domain</th><th>Status</th><th>Priority</th><th>Count</th><th>Stale</th><th>Details</th></tr></thead>
<tbody>${matrixRows}</tbody></table>
<h2>All Workbooks (${allWorkbooks.length})</h2>
<table><thead><tr><th>Name</th><th>Category</th><th>Kind</th><th>Status</th><th>Age</th></tr></thead>
<tbody>${wbRows}</tbody></table>
<div class="footer"><span>Sentinel Vigil · Microsoft Sentinel</span><span>${dateStr}</span></div>
</body></html>`;
        const blob = new Blob([html], { type: 'text/html' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a'); a.href = url;
        a.download = `Workbook_Coverage_${new Date().toISOString().slice(0, 10)}.html`;
        a.click(); URL.revokeObjectURL(url);
    };

    const TABS: Array<{ id: TabId; label: string; icon: any; badge?: string }> = [
        { id: 'coverage',  label: 'Coverage Matrix', icon: faTableCells,
          badge: summary ? `${summary.covered_expected}/${summary.total_expected}` : undefined },
        { id: 'workbooks', label: 'All Workbooks',   icon: faList,
          badge: summary ? String(summary.total_workbooks) : undefined },
        { id: 'activity',  label: 'Recent Activity', icon: faClockRotateLeft },
        { id: 'report',    label: 'AI Report',       icon: faRobot },
    ];

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

            {/* ── Header ── */}
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faBookOpen} style={{ marginRight: 12, fontSize: '0.9em', color: 'var(--pwc-orange)' }} />
                            Workbook Coverage
                        </div>
                        <div className="page-subtitle">
                            Microsoft Sentinel workbooks deployed in the workspace — coverage across {matrix.length} security domains
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: 10 }}>
                        <button className="btn btn-ghost" onClick={exportCoverageHTML} disabled={!summary}>
                            <FontAwesomeIcon icon={faFileCode} style={{ marginRight: 8 }} />
                            Export HTML
                        </button>
                        <button className="btn btn-primary" onClick={fetchCoverage} disabled={loading}>
                            <FontAwesomeIcon icon={faArrowRotateRight} style={{ marginRight: 8 }} />
                            Refresh
                        </button>
                    </div>
                </div>
            </div>

            {loading ? (
                <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12 }}>
                    <div className="spinner spinner-lg" />
                    <div className="text-muted">Fetching workbooks from Sentinel management API…</div>
                </div>
            ) : coverage?.error && !summary?.total_workbooks ? (
                <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 32 }}>
                    {(coverage.error.includes('403') || coverage.error.includes('Forbidden')) ? (
                        <div className="card-elevated" style={{ maxWidth: 560, padding: 28 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                                <FontAwesomeIcon icon={faLock} style={{ fontSize: 28, color: 'var(--high)', flexShrink: 0 }} />
                                <div>
                                    <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 3 }}>Insufficient Permissions</div>
                                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>The service principal cannot read Azure Monitor workbooks</div>
                                </div>
                            </div>
                            <div style={{ background: 'rgba(230,126,34,0.07)', border: '1px solid rgba(230,126,34,0.25)', borderRadius: 8, padding: '12px 14px', marginBottom: 16 }}>
                                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--high)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>Required permission</div>
                                <code style={{ fontSize: 12, color: 'var(--text-primary)', fontFamily: 'monospace' }}>Microsoft.Insights/workbooks/read</code>
                            </div>
                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.8, marginBottom: 16 }}>
                                <div style={{ fontWeight: 700, marginBottom: 6 }}>Assign one of these RBAC roles:</div>
                                {[{ role: 'Monitoring Reader', scope: 'Resource Group (minimum)', recommended: true }, { role: 'Reader', scope: 'Resource Group', recommended: false }].map(r => (
                                    <div key={r.role} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                        <FontAwesomeIcon icon={faCheck} style={{ fontSize: 10, color: r.recommended ? 'var(--low)' : 'var(--text-muted)', flexShrink: 0 }} />
                                        <code style={{ fontSize: 11, color: 'var(--text-primary)', fontFamily: 'monospace', background: 'var(--bg-surface)', padding: '1px 6px', borderRadius: 4 }}>{r.role}</code>
                                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>— {r.scope}</span>
                                        {r.recommended && <span className="badge badge-low" style={{ fontSize: 9 }}>Recommended</span>}
                                    </div>
                                ))}
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px', marginBottom: 16 }}>
                                <span style={{ fontWeight: 600 }}>Steps: </span>
                                Azure Portal → Resource Groups → [your resource group] → Access Control (IAM) → Add role assignment
                            </div>
                            <div style={{ display: 'flex', gap: 10 }}>
                                <button className="btn btn-primary btn-sm" onClick={fetchCoverage}>
                                    <FontAwesomeIcon icon={faArrowRotateRight} style={{ marginRight: 6 }} />Retry
                                </button>
                                <a href="https://portal.azure.com/#view/Microsoft_Azure_AD/RoleAssignmentMenuBlade" target="_blank" rel="noreferrer"
                                    className="btn btn-ghost btn-sm" style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                                    Open Azure IAM <FontAwesomeIcon icon={faArrowUpRightFromSquare} style={{ fontSize: 10 }} />
                                </a>
                            </div>
                        </div>
                    ) : (
                        <div className="card-elevated" style={{ maxWidth: 480, textAlign: 'center', padding: 32 }}>
                            <FontAwesomeIcon icon={faCircleXmark} style={{ fontSize: 32, color: 'var(--critical)', marginBottom: 12 }} />
                            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>Could not fetch workbooks</div>
                            <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>{coverage.error}</div>
                        </div>
                    )}
                </div>
            ) : (
                <>
                    {/* ── KPI Row ── */}
                    {summary && (
                        <div style={{ padding: '16px 28px', borderBottom: '1px solid var(--border)', background: 'var(--bg-base)', flexShrink: 0 }}>
                            {/* Overall coverage progress bar */}
                            <div style={{ marginBottom: 16 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                                    <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                                        Overall Coverage
                                    </div>
                                    <div className="card-metric-value" style={{ fontSize: 18, color: 'var(--pwc-orange)' }}>
                                        {summary.coverage_pct}%
                                    </div>
                                </div>
                                <div className="progress-bar-wrap" style={{ height: 12 }}>
                                    <div className={`progress-bar-fill ${(summary.coverage_pct || 0) >= 80 ? 'green' : (summary.coverage_pct || 0) >= 50 ? 'orange' : 'red'}`}
                                         style={{ width: `${summary.coverage_pct || 0}%` }} />
                                </div>
                            </div>
                            <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                                <ScoreRing pct={summary.coverage_pct} />
                                <div className="stat-grid" style={{ flex: 1, gridTemplateColumns: 'repeat(5, 1fr)' }}>
                                    {[
                                        { label: 'Total Workbooks',    value: summary.total_workbooks, color: 'var(--text-primary)' },
                                        { label: 'Categories Covered', value: `${summary.covered_expected}/${summary.total_expected}`, color: summary.covered_expected >= summary.total_expected ? 'var(--low)' : 'var(--high)' },
                                        { label: 'Coverage Gaps',      value: gaps.length,              color: gaps.length ? 'var(--critical)' : 'var(--low)' },
                                        { label: 'Stale (>90d)',       value: summary.stale_count,      color: summary.stale_count ? 'var(--high)' : 'var(--low)' },
                                        { label: 'Modified (30d)',     value: summary.recent_count,     color: 'var(--info)' },
                                    ].map(k => (
                                        <div key={k.label} className="stat-tile" style={{ padding: 12 }}>
                                            <div className="stat-tile-value" style={{ fontSize: 22, color: k.color }}>{k.value}</div>
                                            <div className="stat-tile-label" style={{ fontSize: 10 }}>{k.label}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* ── Tabs ── */}
                    <div style={{ padding: '0 28px', background: 'var(--bg-base)', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
                        <div className="tabs" style={{ margin: 0 }}>
                            {TABS.map(t => (
                                <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                                    <FontAwesomeIcon icon={t.icon} style={{ marginRight: 7 }} />
                                    {t.label}
                                    {t.badge !== undefined && (
                                        <span className="badge badge-muted" style={{ marginLeft: 7, fontSize: 10, padding: '1px 6px' }}>{t.badge}</span>
                                    )}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* ── Scrollable Content ── */}
                    <div style={{ flex: 1, overflowY: 'auto', padding: '20px 28px' }}>

                        {/* Coverage Matrix */}
                        {tab === 'coverage' && (
                            <div>
                                {gaps.length > 0 && (
                                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 20, background: 'rgba(192,57,43,0.06)', border: '1px solid rgba(192,57,43,0.25)', borderRadius: 8, padding: '12px 16px' }}>
                                        <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: 'var(--critical)', fontSize: 16, flexShrink: 0, marginTop: 2 }} />
                                        <div>
                                            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--critical)', marginBottom: 4 }}>
                                                {gaps.length} coverage gap{gaps.length > 1 ? 's' : ''} detected
                                            </div>
                                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                                {gaps.filter(g => g.priority === 'Critical').length > 0 && <span style={{ fontWeight: 600 }}>Critical: </span>}
                                                {gaps.map(g => g.category).join(' · ')}
                                            </div>
                                        </div>
                                    </div>
                                )}
                                <div style={{ marginBottom: 8, fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                                    Expected Coverage Domains
                                </div>
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12, marginBottom: 24 }}>
                                    {matrix.map(entry => (
                                        <div key={entry.category}
                                            onClick={() => setExpandedCat(expandedCat === entry.category ? null : entry.category)}
                                            className="card-elevated"
                                            style={{ background: entry.covered ? PRIORITY_BG[entry.priority] : 'rgba(192,57,43,0.05)', border: `1.5px solid ${entry.covered ? PRIORITY_COLOR[entry.priority] : 'var(--critical)'}`, borderRadius: 10, padding: '14px 16px', cursor: 'pointer', transition: 'all 0.15s' }}
                                            onMouseEnter={e => (e.currentTarget.style.transform = 'translateY(-1px)')}
                                            onMouseLeave={e => (e.currentTarget.style.transform = '')}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                                                <div style={{ flex: 1 }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                                        <FontAwesomeIcon icon={entry.covered ? faCircleCheck : faCircleXmark} style={{ color: entry.covered ? PRIORITY_COLOR[entry.priority] : 'var(--critical)', fontSize: 14 }} />
                                                        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>{entry.category}</span>
                                                    </div>
                                                    <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: PRIORITY_COLOR[entry.priority], letterSpacing: '0.05em' }}>{entry.priority}</span>
                                                </div>
                                                <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: 12 }}>
                                                    {entry.covered ? (
                                                        <>
                                                            <div className="card-metric-value" style={{ fontSize: 22, color: PRIORITY_COLOR[entry.priority] }}>{entry.count}</div>
                                                            <div className="text-muted" style={{ fontSize: 10 }}>workbook{entry.count !== 1 ? 's' : ''}</div>
                                                        </>
                                                    ) : <span className="badge badge-critical" style={{ fontSize: 11 }}>GAP</span>}
                                                </div>
                                            </div>
                                            {/* Coverage progress bar for covered entries */}
                                            {entry.covered && (
                                                <div className="progress-bar-wrap" style={{ marginBottom: 8, height: 4 }}>
                                                    <div className={`progress-bar-fill ${entry.stale_count > 0 ? 'orange' : 'green'}`}
                                                         style={{ width: entry.stale_count === 0 ? '100%' : `${Math.round(((entry.count - entry.stale_count) / entry.count) * 100)}%` }} />
                                                </div>
                                            )}
                                            {entry.covered && entry.stale_count > 0 && (
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--high)', marginBottom: 8 }}>
                                                    <FontAwesomeIcon icon={faTriangleExclamation} style={{ fontSize: 10 }} />
                                                    {entry.stale_count} workbook{entry.stale_count > 1 ? 's' : ''} not modified in 90+ days
                                                </div>
                                            )}
                                            {!entry.covered && (
                                                <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5, fontStyle: 'italic', marginBottom: 8 }}>{entry.remediation}</div>
                                            )}
                                            {entry.covered && expandedCat === entry.category && (
                                                <div style={{ borderTop: '1px solid var(--border)', paddingTop: 10, marginTop: 4 }}>
                                                    {entry.workbooks.map((w, i) => (
                                                        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6, fontSize: 12 }}>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 0 }}>
                                                                <FontAwesomeIcon icon={w.stale ? faTriangleExclamation : faCheck} style={{ fontSize: 10, color: w.stale ? 'var(--high)' : 'var(--low)', flexShrink: 0 }} />
                                                                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{w.name}</span>
                                                            </div>
                                                            <span className="text-muted" style={{ fontSize: 10, flexShrink: 0, marginLeft: 8 }}>{relativeTime(w.last_modified)}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                            {entry.covered && (
                                                <div className="text-muted" style={{ fontSize: 10, marginTop: 4 }}>
                                                    {expandedCat === entry.category ? 'Click to collapse' : 'Click to expand'}
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                                {coverage!.extra_categories.length > 0 && (
                                    <>
                                        <div style={{ marginBottom: 8, fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Additional Deployed Workbooks</div>
                                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                            {coverage!.extra_categories.map(e => (
                                                <div key={e.category} style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 20, padding: '4px 12px', fontSize: 12 }}>
                                                    <FontAwesomeIcon icon={faBookOpen} style={{ color: 'var(--pwc-orange)', fontSize: 10 }} />
                                                    <span style={{ fontWeight: 600 }}>{e.category}</span>
                                                    <span className="badge badge-muted" style={{ fontSize: 10, padding: '1px 5px' }}>{e.count}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </>
                                )}
                            </div>
                        )}

                        {/* All Workbooks */}
                        {tab === 'workbooks' && (
                            <div>
                                <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
                                    <div style={{ position: 'relative', flex: '1 1 220px', minWidth: 180 }}>
                                        <FontAwesomeIcon icon={faMagnifyingGlass} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 12 }} />
                                        <input className="form-input" placeholder="Search workbooks…" value={search} onChange={e => setSearch(e.target.value)} style={{ paddingLeft: 30, height: 34 }} />
                                    </div>
                                    <div className="text-muted" style={{ fontSize: 12 }}>{filteredWorkbooks.length} of {allWorkbooks.length}</div>
                                </div>
                                {/* Category chips */}
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
                                    {categories.map(c => (
                                        <button
                                            key={c}
                                            className={`chip ${catFilter === c ? 'active' : ''}`}
                                            onClick={() => setCatFilter(c)}
                                        >
                                            {c}
                                        </button>
                                    ))}
                                </div>
                                {filteredWorkbooks.length === 0 ? (
                                    <div className="empty-state">
                                        <div className="empty-state-icon"><FontAwesomeIcon icon={faBookOpen} style={{ opacity: 0.3 }} /></div>
                                        <div className="empty-state-text">No workbooks match the current filters</div>
                                    </div>
                                ) : (
                                    <div className="card" style={{ padding: 0 }}>
                                        <div className="data-table-wrap">
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th>Workbook Name</th>
                                                        <th style={{ width: 160 }}>Category</th>
                                                        <th style={{ width: 100 }}>Kind</th>
                                                        <th style={{ width: 80 }}>Status</th>
                                                        <th style={{ width: 120 }}>Last Modified</th>
                                                        <th style={{ width: 80 }}>Age</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {filteredWorkbooks.map((w, i) => (
                                                        <tr key={i}>
                                                            <td>
                                                                <div style={{ fontSize: 12, fontWeight: 600 }}>{w.name}</div>
                                                                {w.description && <div className="text-muted" style={{ fontSize: 10, marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 340 }}>{w.description}</div>}
                                                            </td>
                                                            <td><span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{w.category}</span></td>
                                                            <td><span className="badge badge-muted" style={{ fontSize: 10 }}>{w.kind}</span></td>
                                                            <td>
                                                                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                                    <div className={`health-light ${w.stale ? 'yellow' : 'green'}`} />
                                                                    {w.stale ? (
                                                                        <span className="badge badge-high" style={{ fontSize: 10, display: 'flex', alignItems: 'center', gap: 5, width: 'fit-content' }}>
                                                                            <FontAwesomeIcon icon={faTriangleExclamation} style={{ fontSize: 9 }} />Stale
                                                                        </span>
                                                                    ) : (
                                                                        <span className="badge badge-low" style={{ fontSize: 10, display: 'flex', alignItems: 'center', gap: 5, width: 'fit-content' }}>
                                                                            <FontAwesomeIcon icon={faCheck} style={{ fontSize: 9 }} />Current
                                                                        </span>
                                                                    )}
                                                                </div>
                                                            </td>
                                                            <td className="text-muted" style={{ fontSize: 11 }}>{relativeTime(w.last_modified)}</td>
                                                            <td style={{ fontSize: 11, color: w.stale ? 'var(--high)' : 'var(--text-muted)' }}>
                                                                {w.days_since_modified !== null ? `${w.days_since_modified}d` : '—'}
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

                        {/* Recent Activity */}
                        {tab === 'activity' && (
                            actLoading ? (
                                <div style={{ padding: 60, textAlign: 'center' }}>
                                    <div className="spinner spinner-lg" style={{ margin: '0 auto 12px' }} />
                                    <div className="text-muted">Querying AzureActivity logs…</div>
                                </div>
                            ) : activity.length === 0 ? (
                                <div className="empty-state">
                                    <div className="empty-state-icon"><FontAwesomeIcon icon={faClockRotateLeft} style={{ opacity: 0.3 }} /></div>
                                    <div className="empty-state-text">No workbook activity found in the last 30 days</div>
                                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
                                        Workbook reads are not logged — only creates, updates, and deletes appear here.
                                    </div>
                                </div>
                            ) : (
                                <div>
                                    <div className="text-muted" style={{ fontSize: 12, marginBottom: 14 }}>
                                        Workbook creates, updates, and deletes from AzureActivity (last 30 days). Read-only access is not logged by Azure.
                                    </div>
                                    <div className="card" style={{ padding: 0 }}>
                                        <div className="data-table-wrap">
                                            <table className="data-table">
                                                <thead>
                                                    <tr>
                                                        <th>Operation</th><th>Workbook</th>
                                                        <th style={{ width: 90 }}>Status</th><th>Caller</th>
                                                        <th style={{ width: 80 }}>Count</th><th style={{ width: 110 }}>Last Seen</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {activity.map((a, i) => {
                                                        const isDelete = a.operation.toLowerCase().includes('delete');
                                                        const isWrite  = a.operation.toLowerCase().includes('write');
                                                        return (
                                                            <tr key={i}>
                                                                <td><span className={`badge ${isDelete ? 'badge-critical' : isWrite ? 'badge-medium' : 'badge-muted'}`} style={{ fontSize: 10 }}>{opLabel(a.operation)}</span></td>
                                                                <td style={{ fontSize: 12 }}>{a.resource || '—'}</td>
                                                                <td><span className={`badge ${a.status === 'Success' ? 'badge-low' : 'badge-critical'}`} style={{ fontSize: 10 }}>
                                                                    <FontAwesomeIcon icon={a.status === 'Success' ? faCheck : faXmark} style={{ marginRight: 4, fontSize: 9 }} />{a.status}
                                                                </span></td>
                                                                <td className="text-muted" style={{ fontSize: 11 }}>{a.caller || '—'}</td>
                                                                <td style={{ fontSize: 12, fontWeight: 600 }}>{a.count}</td>
                                                                <td className="text-muted" style={{ fontSize: 11 }}>{relativeTime(a.last_seen)}</td>
                                                            </tr>
                                                        );
                                                    })}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            )
                        )}

                        {/* AI Report */}
                        {tab === 'report' && <AiReportTab />}

                    </div>
                </>
            )}
        </div>
    );
}
