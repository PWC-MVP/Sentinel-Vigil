"""
MITRE ATT&CK Coverage router.
GET  /api/mitre/data          → return structured coverage data
POST /api/mitre/generate      → generate HTML report, return path
GET  /api/mitre/reports       → list existing MITRE HTML/SVG reports
"""
import json
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse

from backend.config import settings
from backend.services.sentinel import run_kql, call_sentinel_mgmt_api_async

router = APIRouter(prefix="/api/mitre", tags=["mitre"])
logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent   # project root


# ── MITRE Framework data (imported from generate_mitre_coverage_report.py) ───
def _load_coverage_data() -> dict:
    """Load and return MITRE coverage data from the existing Python module."""
    sys.path.insert(0, str(ROOT))
    try:
        import generate_mitre_coverage_report as m
        return {
            "tactics": [
                {
                    "id": tac_id,
                    "name": data["name"],
                    "coverage": data["coverage"],
                    "incidents": data["incidents"],
                    "techniques_total": data["techniques"],
                    "techniques_covered": data["covered_techniques"],
                    "techniques_list": [
                        {
                            "id": t[0],
                            "name": t[1],
                            "covered": t[2],
                            "score": t[3],
                        }
                        for t in data["techniques_list"]
                    ],
                }
                for tac_id, data in m.MITRE_COVERAGE_DATA.items()
            ],
            "recommended_rules": m.RECOMMENDED_RULES,
            "missing_log_sources": m.MISSING_LOG_SOURCES,
            "summary": _build_summary(m.MITRE_COVERAGE_DATA),
        }
    except Exception as e:
        logger.error("Failed to load MITRE data: %s", e)
        return {"error": str(e), "tactics": [], "recommended_rules": [], "summary": {}}


def _build_summary(data: dict) -> dict:
    coverages = [v["coverage"] for v in data.values()]
    total_techniques = sum(v["techniques"] for v in data.values())
    covered_techniques = sum(v["covered_techniques"] for v in data.values())
    total_incidents = sum(v["incidents"] for v in data.values())
    overall = round(sum(coverages) / len(coverages), 1) if coverages else 0
    return {
        "overall_coverage": overall,
        "total_tactics": len(data),
        "tactics_with_coverage": sum(1 for v in data.values() if v["coverage"] > 0),
        "total_techniques": total_techniques,
        "covered_techniques": covered_techniques,
        "total_incidents": total_incidents,
        "assessment": (
            "CRITICAL" if overall < 30
            else "HIGH" if overall < 50
            else "MEDIUM" if overall < 70
            else "LOW"
        ),
    }


@router.get("/data")
async def get_mitre_data():
    """Return structured MITRE coverage data for frontend visualization."""
    return _load_coverage_data()


@router.post("/generate")
async def generate_mitre_report():
    """
    Run the existing generate_mitre_coverage_report.py and generate_mitre_heatmap.py
    scripts and return the paths to the generated files.
    """
    import asyncio
    import os as _os
    from backend.config import settings
    sys.path.insert(0, str(ROOT))
    reports_dir = settings.OUTPUT_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    generated = []

    # Force UTF-8 encoding
    import os as _os
    _env = {**_os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}

    import subprocess
    loop = asyncio.get_event_loop()

    # Run HTML report generator
    try:
        def run_html_gen():
            return subprocess.run(
                [sys.executable, str(ROOT / "generate_mitre_coverage_report.py"), str(reports_dir)],
                cwd=str(ROOT),
                capture_output=True,
                env=_env,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

        res = await loop.run_in_executor(None, run_html_gen)
        
        if res.returncode == 0:
            # Find the file most recently created in the reports_dir
            html_files = sorted(reports_dir.glob("MITRE_ATT_CK_Coverage_Report*.html"),
                                key=lambda f: f.stat().st_mtime, reverse=True)
            if html_files:
                generated.append({"type": "html", "name": html_files[0].name, "path": str(html_files[0])})
        else:
            logger.error(f"HTML generator failed (code {res.returncode}): {res.stderr}")
    except Exception as e:
        logger.error("HTML generator exception: %s", e)

    # Run heatmap generator
    try:
        def run_heatmap_gen():
            return subprocess.run(
                [sys.executable, str(ROOT / "generate_mitre_heatmap.py"), str(reports_dir)],
                cwd=str(ROOT),
                capture_output=True,
                env=_env,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

        res = await loop.run_in_executor(None, run_heatmap_gen)
        
        if res.returncode == 0:
            svg_files = sorted(reports_dir.glob("MITRE_Coverage_Heatmap*.svg"),
                               key=lambda f: f.stat().st_mtime, reverse=True)
            for f in svg_files[:2]:
                generated.append({"type": "svg", "name": f.name, "path": str(f)})
    except Exception as e:
        logger.error("Heatmap generator exception: %s", e)

    return {
        "generated": generated,
        "count": len(generated),
        "message": f"Generated {len(generated)} MITRE report file(s)",
    }


@router.get("/reports")
async def list_mitre_reports():
    """List all existing MITRE report files."""
    reports_dir = ROOT / "reports"
    if not reports_dir.exists():
        return {"reports": []}

    files = []
    for pattern in ["MITRE_*.html", "MITRE_*.svg", "MITRE_*.txt", "MITRE_*.pdf"]:
        for f in reports_dir.glob(pattern):
            files.append({
                "name": f.name,
                "type": f.suffix.lstrip("."),
                "size_bytes": f.stat().st_size,
                "created": f.stat().st_mtime,
                "relative_path": f.name,
            })

    files.sort(key=lambda x: x["created"], reverse=True)
    return {"reports": files}


async def _gather_report_data() -> dict:
    """Fetch all live data needed for the comprehensive HTML export in parallel."""
    import asyncio

    coverage = _load_coverage_data()

    uc_task   = asyncio.create_task(get_use_cases())
    fp_task   = asyncio.create_task(get_false_positives(days=90))
    tech_task = asyncio.create_task(get_technique_activity(days=30))

    use_cases, fp_data, tech_data = await asyncio.gather(uc_task, fp_task, tech_task)

    return {
        "generated_at": datetime.now().strftime("%B %d, %Y %H:%M UTC"),
        "coverage":     coverage,
        "use_cases":    use_cases,
        "fp":           fp_data,
        "tech":         tech_data,
    }


def _build_html_report(data: dict) -> str:  # noqa: C901
    """Comprehensive self-contained HTML with 7 JS tabs covering all report sections."""
    gen_at  = data["generated_at"]
    cov     = data["coverage"]
    uc      = data["use_cases"]
    fp      = data["fp"]
    tech    = data["tech"]
    summary = cov.get("summary", {})
    tactics = cov.get("tactics", [])
    rec     = cov.get("recommended_rules", [])
    ls      = cov.get("missing_log_sources", [])
    uc_sum  = uc.get("summary", {})
    fp_sum  = fp.get("summary", {})

    def _esc(s: Any) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def _pri_color(p: str) -> str:
        return {
            "CRITICAL": "#ef4444", "HIGH": "#f59e0b", "MEDIUM": "#3b82f6", "LOW": "#22c55e",
            "Critical": "#ef4444", "High": "#ef4444", "Medium": "#f59e0b",
            "Low": "#3b82f6", "Informational": "#6b7280",
        }.get(str(p), "#6b7280")

    def _cov_color(pct: float) -> str:
        if pct >= 70: return "#22c55e"
        if pct >= 40: return "#f59e0b"
        return "#ef4444"

    def _score_bg(score: int, covered: bool) -> str:
        if not covered: return "#0f172a"
        if score >= 80: return "#14532d"
        if score >= 60: return "#166534"
        if score >= 40: return "#854d0e"
        return "#7c2d12"

    # ── CSS variables + rules (plain string — no f-string escaping needed) ──────
    css = (
        # ── Theme tokens ────────────────────────────────────────────────────
        ":root{"
        "--bg-base:#0f172a;--bg-card:#1e293b;--bg-raised:#162032;--bg-deep:#0a1120;"
        "--bg-hover:#1e3a5f20;--bg-accent:#1e3a5f;"
        "--border:#334155;--border-light:#1e293b;"
        "--text-primary:#e2e8f0;--text-secondary:#94a3b8;--text-muted:#64748b;"
        "--text-td:#cbd5e1;"
        "--kql-bg:#0a1120;--kql-color:#93c5fd;--kql-border:#1e3a5f;"
        "--code-color:#93c5fd;--code-bg:#1e3a5f;"
        "--tab-nav-bg:#0a1120;--tab-btn-color:#64748b;--tab-btn-hover:#94a3b8;"
        "--h2-border:#1e293b;--h2-color:#e2e8f0;"
        "--ring-text:#e2e8f0;"
        "--tooltip-bg:#0a1120;--tooltip-border:#334155;"
        "}"
        # ── Light mode overrides ─────────────────────────────────────────────
        "[data-theme=light]{"
        "--bg-base:#f8fafc;--bg-card:#ffffff;--bg-raised:#f1f5f9;--bg-deep:#f1f5f9;"
        "--bg-hover:#e0f2fe60;--bg-accent:#dbeafe;"
        "--border:#e2e8f0;--border-light:#e2e8f0;"
        "--text-primary:#0f172a;--text-secondary:#475569;--text-muted:#94a3b8;"
        "--text-td:#374151;"
        "--kql-bg:#f0f9ff;--kql-color:#1d4ed8;--kql-border:#bfdbfe;"
        "--code-color:#1d4ed8;--code-bg:#dbeafe;"
        "--tab-nav-bg:#ffffff;--tab-btn-color:#64748b;--tab-btn-hover:#374151;"
        "--h2-border:#e2e8f0;--h2-color:#0f172a;"
        "--ring-text:#0f172a;"
        "--tooltip-bg:#1e293b;--tooltip-border:#e2e8f0;"
        "}"
        # ── Base ─────────────────────────────────────────────────────────────
        "*{box-sizing:border-box;margin:0;padding:0}"
        "body{background:var(--bg-base);color:var(--text-primary);"
        "font-family:'Segoe UI',Arial,sans-serif;font-size:14px;line-height:1.6;"
        "transition:background 0.25s,color 0.25s}"
        "a{color:#60a5fa;text-decoration:none}"
        # ── Topbar (always dark — branding) ──────────────────────────────────
        ".topbar{background:linear-gradient(135deg,#1a2535 0%,#0f172a 100%);"
        "border-bottom:3px solid #d04a02;padding:14px 32px;display:flex;"
        "align-items:center;gap:16px;position:sticky;top:0;z-index:200}"
        ".topbar-brand{font-size:22px;font-weight:900;color:#d04a02;letter-spacing:-0.5px}"
        ".topbar-title{font-size:17px;font-weight:700;color:#fff}"
        ".topbar-sub{font-size:12px;color:#94a3b8;margin-top:2px}"
        ".topbar-meta{margin-left:auto;font-size:12px;color:#94a3b8;text-align:right}"
        # ── Theme toggle button ───────────────────────────────────────────────
        ".theme-toggle{display:flex;align-items:center;gap:7px;background:#ffffff18;"
        "border:1px solid #ffffff30;border-radius:999px;padding:6px 14px;"
        "color:#e2e8f0;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;"
        "transition:all 0.2s;flex-shrink:0}"
        ".theme-toggle:hover{background:#ffffff28;border-color:#ffffff50}"
        ".theme-toggle .icon{font-size:15px;line-height:1}"
        # ── Tab navigation ────────────────────────────────────────────────────
        ".tab-nav{background:var(--tab-nav-bg);border-bottom:1px solid var(--border-light);"
        "padding:0 32px;display:flex;gap:0;position:sticky;top:64px;z-index:190;"
        "overflow-x:auto;transition:background 0.25s}"
        ".tab-btn{background:none;border:none;color:var(--tab-btn-color);font-size:11px;"
        "font-weight:700;padding:13px 18px;cursor:pointer;border-bottom:2px solid transparent;"
        "transition:all 0.15s;white-space:nowrap;text-transform:uppercase;letter-spacing:0.06em}"
        ".tab-btn:hover{color:var(--tab-btn-hover)}"
        ".tab-btn.active{color:#d04a02;border-bottom-color:#d04a02}"
        ".tab-pane{display:none;padding:28px 32px;max-width:1400px;margin:0 auto}"
        ".tab-pane.active{display:block}"
        # ── Typography ────────────────────────────────────────────────────────
        "h2{font-size:17px;font-weight:700;color:var(--h2-color);margin:0 0 16px;"
        "padding-bottom:10px;border-bottom:1px solid var(--h2-border)}"
        "h3{font-size:13px;font-weight:700;color:var(--text-secondary);margin:0 0 10px;"
        "text-transform:uppercase;letter-spacing:0.05em}"
        # ── KPI tiles ─────────────────────────────────────────────────────────
        ".kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));"
        "gap:12px;margin-bottom:20px}"
        ".kpi{background:var(--bg-card);border-radius:10px;padding:14px 18px;"
        "border:1px solid var(--border);transition:background 0.25s,border 0.25s}"
        ".kpi-label{font-size:10px;color:var(--text-muted);text-transform:uppercase;"
        "letter-spacing:0.5px;margin-bottom:4px}"
        ".kpi-value{font-size:26px;font-weight:800;color:var(--text-primary)}"
        # ── Card ──────────────────────────────────────────────────────────────
        ".card{background:var(--bg-card);border-radius:10px;padding:18px 22px;"
        "border:1px solid var(--border);margin-bottom:16px;transition:background 0.25s,border 0.25s}"
        # ── Table ─────────────────────────────────────────────────────────────
        "table{width:100%;border-collapse:collapse;font-size:12px}"
        "th{background:var(--bg-deep);color:var(--text-muted);text-align:left;padding:8px 10px;"
        "font-size:10px;text-transform:uppercase;letter-spacing:0.5px;font-weight:700;"
        "position:sticky;top:0;z-index:1;transition:background 0.25s}"
        "td{padding:8px 10px;border-bottom:1px solid var(--border-light);"
        "vertical-align:middle;color:var(--text-td)}"
        "tr:last-child td{border-bottom:none}tr:hover td{background:var(--bg-hover)}"
        # ── Badges ────────────────────────────────────────────────────────────
        ".badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700}"
        ".bg{background:#14532d;color:#4ade80}.br{background:#450a0a;color:#f87171}"
        ".bb{background:var(--code-bg);color:var(--code-color)}"
        # ── Ring chart ───────────────────────────────────────────────────────
        ".ring-wrap{display:flex;align-items:center;gap:28px;margin-bottom:20px}"
        ".ring-meta p{margin:5px 0;font-size:13px;color:var(--text-secondary)}"
        ".ring-meta strong{color:var(--text-primary)}"
        # ── Bar chart rows ────────────────────────────────────────────────────
        ".bar-row{display:flex;align-items:center;gap:8px;margin-bottom:7px}"
        ".bar-lbl{font-size:11px;color:var(--text-secondary);width:160px;text-align:right;flex-shrink:0}"
        ".bar-trk{flex:1;height:14px;background:var(--bg-deep);border-radius:7px;overflow:hidden;"
        "transition:background 0.25s}"
        ".bar-fill{height:100%;border-radius:7px}"
        ".bar-val{font-size:11px;font-weight:700;width:44px;text-align:right;flex-shrink:0}"
        # ── Heatmap ───────────────────────────────────────────────────────────
        ".hm-grid{display:flex;flex-direction:column;gap:12px}"
        ".hm-tac{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;"
        "overflow:hidden;transition:background 0.25s,border 0.25s}"
        ".hm-hdr{padding:12px 16px;display:flex;align-items:center;gap:10px;cursor:pointer}"
        ".hm-hdr:hover{background:var(--bg-hover)}"
        ".hm-id{font-size:10px;font-weight:800;color:var(--text-muted);width:52px;flex-shrink:0}"
        ".hm-name{font-size:13px;font-weight:700;color:var(--text-primary);flex:1}"
        ".hm-bar-trk{width:150px;height:7px;background:var(--bg-deep);border-radius:4px;"
        "overflow:hidden;flex-shrink:0;transition:background 0.25s}"
        ".hm-bar-fill{height:100%;border-radius:4px}"
        ".hm-pct{font-size:13px;font-weight:800;width:42px;text-align:right;flex-shrink:0}"
        ".hm-inc{font-size:10px;color:var(--text-muted);width:90px;text-align:right;flex-shrink:0}"
        ".tech-grid{display:flex;flex-wrap:wrap;gap:4px;padding:12px 16px;"
        "background:var(--bg-raised);border-top:1px solid var(--border-light);"
        "transition:background 0.25s}"
        ".tp{display:inline-block;padding:4px 8px;border-radius:5px;font-size:10px;"
        "font-weight:600;cursor:default;position:relative}"
        ".tp:hover::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 6px);"
        "left:50%;transform:translateX(-50%);background:var(--tooltip-bg);"
        "color:var(--text-primary);padding:5px 10px;border-radius:6px;font-size:11px;"
        "white-space:nowrap;border:1px solid var(--tooltip-border);z-index:999;pointer-events:none}"
        # ── Recommended rule cards ────────────────────────────────────────────
        ".rule-card{background:var(--bg-card);border:1px solid var(--border);"
        "border-radius:10px;margin-bottom:14px;overflow:hidden;"
        "transition:background 0.25s,border 0.25s}"
        ".rule-hdr{padding:14px 18px;display:flex;align-items:flex-start;gap:12px}"
        ".rule-pri{font-size:10px;font-weight:800;padding:3px 10px;border-radius:999px;"
        "flex-shrink:0;text-transform:uppercase}"
        ".rule-meta-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));"
        "gap:12px;padding:14px 18px;background:var(--bg-raised);"
        "border-top:1px solid var(--border-light);transition:background 0.25s}"
        ".rml{font-size:10px;color:var(--text-muted);text-transform:uppercase;"
        "letter-spacing:0.4px;margin-bottom:3px}"
        ".rmv{font-size:12px;color:var(--text-secondary)}"
        # ── KQL block ─────────────────────────────────────────────────────────
        ".kql-wrap{padding:14px 18px;border-top:1px solid var(--border-light)}"
        ".kql-block{background:var(--kql-bg);border:1px solid var(--kql-border);"
        "border-radius:6px;padding:12px 14px;font-size:11px;"
        "font-family:'JetBrains Mono',Consolas,monospace;white-space:pre-wrap;"
        "word-break:break-all;color:var(--kql-color);line-height:1.6;margin-top:6px;"
        "overflow-x:auto;transition:background 0.25s,color 0.25s,border 0.25s}"
        # ── FP comments ───────────────────────────────────────────────────────
        ".fp-comment{background:var(--bg-raised);border-left:3px solid var(--border);"
        "border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:10px;"
        "transition:background 0.25s}"
        # ── Print ─────────────────────────────────────────────────────────────
        "@media print{"
        ".topbar,.tab-nav,.theme-toggle{display:none!important}"
        ".tab-pane{display:block!important;page-break-after:always}"
        "body{background:#fff!important;color:#000!important}"
        ".card,.kpi,.rule-card,.hm-tac{background:#f8fafc!important;border-color:#e2e8f0!important}"
        ".kql-block{background:#f0f9ff!important;color:#1d4ed8!important}}"
    )

    # ── JavaScript ────────────────────────────────────────────────────────────
    js = (
        # Tab switching
        "function showTab(id,btn){"
        "document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));"
        "document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));"
        "document.getElementById('t-'+id).classList.add('active');btn.classList.add('active');}"
        # Heatmap row toggle
        "function tog(idx){"
        "var g=document.getElementById('g-'+idx),a=document.getElementById('a-'+idx);"
        "if(g.style.display==='none'){g.style.display='flex';a.textContent='▲';}"
        "else{g.style.display='none';a.textContent='▼';}}"
        # Theme toggle
        "function toggleTheme(){"
        "var html=document.documentElement;"
        "var isDark=html.getAttribute('data-theme')!=='light';"
        "var next=isDark?'light':'dark';"
        "html.setAttribute('data-theme',next);"
        "localStorage.setItem('mitre-theme',next);"
        "var btn=document.getElementById('theme-btn');"
        "btn.querySelector('.icon').textContent=next==='light'?'🌙':'☀️';"
        "btn.querySelector('.lbl').textContent=next==='light'?'Dark Mode':'Light Mode';}"
        # Apply saved theme on load
        "(function(){"
        "var saved=localStorage.getItem('mitre-theme')||'dark';"
        "document.documentElement.setAttribute('data-theme',saved);"
        "document.addEventListener('DOMContentLoaded',function(){"
        "var btn=document.getElementById('theme-btn');"
        "if(btn){"
        "btn.querySelector('.icon').textContent=saved==='light'?'🌙':'☀️';"
        "btn.querySelector('.lbl').textContent=saved==='light'?'Dark Mode':'Light Mode';"
        "}})"
        "})()"
    )

    # ── Pre-compute all sections ──────────────────────────────────────────────

    overall_cov = summary.get("overall_coverage", 0)
    rp          = round(min(overall_cov, 100))
    C           = 2 * 3.14159 * 54
    df          = round(C * rp / 100, 1)
    cc          = _cov_color(overall_cov)
    fp_tot      = fp_sum.get("total", 0)
    tp_v        = fp_sum.get("true_positive", 0)
    fp_v        = fp_sum.get("false_positive", 0)
    bp_v        = fp_sum.get("benign_positive", 0)
    ud_v        = fp_sum.get("undetermined", 0)
    uc_v        = fp_sum.get("unclassified", 0)

    def _bar(label, val, total, color):
        w = round(100 * val / max(total, 1))
        return (
            f'<div class="bar-row"><div class="bar-lbl">{_esc(label)}</div>'
            f'<div class="bar-trk"><div class="bar-fill" style="width:{w}%;background:{color}"></div></div>'
            f'<div class="bar-val" style="color:{color}">{val:,}</div></div>'
        )

    # Tactic coverage bars
    tac_bars = "".join(
        _bar(t.get("name",""), t.get("coverage",0), 100, _cov_color(t.get("coverage",0)))
        for t in sorted(tactics, key=lambda x: -x.get("coverage",0))
    )

    # Rules-by-kind bars
    kind_bars = "".join(
        _bar(k, v, max(uc_sum.get("total",1),1), "#3b82f6")
        for k, v in uc_sum.get("by_kind",{}).items()
    )

    # ── TAB 1: Overview ───────────────────────────────────────────────────────
    ena_pct = round(100 * uc_sum.get("enabled",0) / max(uc_sum.get("total",1),1))
    tab1 = (
        f'<div class="ring-wrap">'
        f'<svg width="130" height="130" viewBox="0 0 128 128">'
        f'<circle cx="64" cy="64" r="54" fill="none" stroke="#1e293b" stroke-width="12"/>'
        f'<circle cx="64" cy="64" r="54" fill="none" stroke="{cc}" stroke-width="12"'
        f' stroke-dasharray="{df} {round(C,1)}" stroke-dashoffset="{round(C/4,1)}" stroke-linecap="round"/>'
        f'<text x="64" y="58" text-anchor="middle" fill="#e2e8f0" font-size="20" font-weight="800">{rp}%</text>'
        f'<text x="64" y="74" text-anchor="middle" fill="#94a3b8" font-size="11">Coverage</text>'
        f'</svg>'
        f'<div class="ring-meta">'
        f'<p>Overall: <strong style="color:{cc}">{overall_cov}%</strong></p>'
        f'<p>Risk: <strong style="color:{cc}">{_esc(summary.get("assessment","—"))}</strong></p>'
        f'<p>Tactics: <strong>{summary.get("tactics_with_coverage",0)}/{summary.get("total_tactics",0)}</strong></p>'
        f'<p>Techniques: <strong>{summary.get("covered_techniques",0)}/{summary.get("total_techniques",0)}</strong></p>'
        f'<p>Incidents: <strong>{summary.get("total_incidents",0):,}</strong></p>'
        f'</div></div>'
        f'<div class="kpi-grid">'
        f'<div class="kpi"><div class="kpi-label">Analytics Rules</div><div class="kpi-value">{uc_sum.get("total",0)}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Enabled</div><div class="kpi-value" style="color:#22c55e">{uc_sum.get("enabled",0)}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Disabled</div><div class="kpi-value" style="color:#ef4444">{uc_sum.get("disabled",0)}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Enabled %</div><div class="kpi-value" style="color:{"#22c55e" if ena_pct>=80 else "#f59e0b"}">{ena_pct}%</div></div>'
        f'<div class="kpi"><div class="kpi-label">FP Rate (90d)</div><div class="kpi-value" style="color:#f59e0b">{fp_sum.get("fp_rate",0):.1f}%</div></div>'
        f'<div class="kpi"><div class="kpi-label">TP Rate (90d)</div><div class="kpi-value" style="color:#22c55e">{fp_sum.get("tp_rate",0):.1f}%</div></div>'
        f'<div class="kpi"><div class="kpi-label">Total Incidents</div><div class="kpi-value">{fp_tot:,}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Rec. Rules</div><div class="kpi-value" style="color:#f59e0b">{len(rec)}</div></div>'
        f'</div>'
        f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">'
        f'<div class="card"><h3>Tactic Coverage</h3>{tac_bars}</div>'
        f'<div class="card"><h3>Rules by Kind</h3>{kind_bars}'
        f'<div style="margin-top:16px;padding-top:14px;border-top:1px solid #1e293b"><h3>Incident Classification (90d)</h3>'
        + _bar("True Positive",  tp_v, fp_tot, "#22c55e")
        + _bar("False Positive", fp_v, fp_tot, "#ef4444")
        + _bar("Benign Positive",bp_v, fp_tot, "#f59e0b")
        + _bar("Undetermined",   ud_v, fp_tot, "#64748b")
        + _bar("Unclassified",   uc_v, fp_tot, "#334155")
        + f'</div></div></div>'
    )

    # ── TAB 2: Heatmap ────────────────────────────────────────────────────────
    hm_rows = ""
    for idx, tac in enumerate(tactics):
        cp    = tac.get("coverage", 0)
        tc    = _cov_color(cp)
        pills = ""
        for t in tac.get("techniques_list", []):
            bg   = _score_bg(t.get("score",0), t.get("covered",False))
            txc  = "#4ade80" if t.get("covered") else "#64748b"
            tip  = f'{t.get("id","")} · {t.get("name","")} · {t.get("score",0)}%'
            pills += (
                f'<div class="tp" style="background:{bg};color:{txc}" data-tip="{_esc(tip)}">'
                f'{_esc(t.get("id",""))}</div>'
            )
        hm_rows += (
            f'<div class="hm-tac">'
            f'<div class="hm-hdr" onclick="tog({idx})">'
            f'<div class="hm-id">{_esc(tac.get("id",""))}</div>'
            f'<div class="hm-name">{_esc(tac.get("name",""))}</div>'
            f'<div class="hm-bar-trk"><div class="hm-bar-fill" style="width:{cp}%;background:{tc}"></div></div>'
            f'<div class="hm-pct" style="color:{tc}">{cp}%</div>'
            f'<div class="hm-inc">{tac.get("incidents",0):,} incidents</div>'
            f'<span style="color:var(--text-muted);font-size:10px">{tac.get("techniques_covered",0)}/{tac.get("techniques_total",0)} tech</span>'
            f'<span id="a-{idx}" style="color:var(--text-muted);margin-left:8px;font-size:10px">▼</span>'
            f'</div>'
            f'<div id="g-{idx}" class="tech-grid" style="display:none">{pills}</div>'
            f'</div>'
        )
    legend = (
        '<div style="margin-top:16px;display:flex;gap:16px;flex-wrap:wrap;font-size:11px;color:#94a3b8">'
        '<strong>Legend:</strong>'
        '<span style="display:flex;align-items:center;gap:5px"><span style="width:12px;height:12px;background:#14532d;border-radius:3px;display:inline-block"></span>≥80%</span>'
        '<span style="display:flex;align-items:center;gap:5px"><span style="width:12px;height:12px;background:#166534;border-radius:3px;display:inline-block"></span>60–79%</span>'
        '<span style="display:flex;align-items:center;gap:5px"><span style="width:12px;height:12px;background:#854d0e;border-radius:3px;display:inline-block"></span>40–59%</span>'
        '<span style="display:flex;align-items:center;gap:5px"><span style="width:12px;height:12px;background:#7c2d12;border-radius:3px;display:inline-block"></span>&lt;40%</span>'
        '<span style="display:flex;align-items:center;gap:5px"><span style="width:12px;height:12px;background:#0f172a;border:1px solid #334155;border-radius:3px;display:inline-block"></span>Not covered</span>'
        '</div>'
    )
    tab2 = f'<div class="hm-grid">{hm_rows}</div>{legend}'

    # ── TAB 3: Tactic Detail ──────────────────────────────────────────────────
    tac_cards = ""
    for tac in tactics:
        cp = tac.get("coverage", 0)
        tc = _cov_color(cp)
        trows = ""
        for t in tac.get("techniques_list", []):
            dot  = "#22c55e" if t.get("covered") else "#475569"
            sw   = min(t.get("score",0), 100)
            sc2  = _cov_color(t.get("score",0)) if t.get("covered") else "#334155"
            trows += (
                f'<tr>'
                f'<td><code style="color:var(--code-color);background:var(--code-bg);padding:2px 5px;border-radius:3px;font-size:10px">{_esc(t.get("id",""))}</code></td>'
                f'<td style="color:var(--text-primary)">{_esc(t.get("name",""))}</td>'
                f'<td><span style="color:{dot};font-weight:700">{"✓" if t.get("covered") else "✗"}</span></td>'
                f'<td><div style="display:flex;align-items:center;gap:8px">'
                f'<div style="width:70px;height:5px;background:var(--bg-deep);border-radius:3px">'
                f'<div style="width:{sw}%;height:5px;background:{sc2};border-radius:3px"></div></div>'
                f'<span style="color:{sc2};font-size:11px;font-weight:700">{t.get("score",0)}%</span>'
                f'</div></td>'
                f'</tr>'
            )
        tac_cards += (
            f'<div class="card">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">'
            f'<div><code style="font-size:10px;color:var(--text-muted);background:var(--bg-deep);padding:2px 7px;border-radius:4px">{_esc(tac.get("id",""))}</code>'
            f'<span style="font-size:14px;font-weight:700;color:var(--text-primary);margin-left:10px">{_esc(tac.get("name",""))}</span>'
            f'<span style="font-size:11px;color:var(--text-muted);margin-left:10px">{tac.get("techniques_covered",0)}/{tac.get("techniques_total",0)} techniques · {tac.get("incidents",0):,} incidents</span>'
            f'</div><div style="font-size:26px;font-weight:800;color:{tc}">{cp}%</div></div>'
            f'<table><thead><tr><th>ID</th><th>Technique</th><th>Status</th><th>Score</th></tr></thead>'
            f'<tbody>{trows}</tbody></table></div>'
        )
    tab3 = tac_cards or '<div class="card" style="color:#64748b;text-align:center;padding:24px">No tactic data available.</div>'

    # ── TAB 4: Analytics Rules ────────────────────────────────────────────────
    kp = "".join(
        f'<span class="badge bb" style="margin-right:6px">{_esc(k)}: {v}</span>'
        for k, v in uc_sum.get("by_kind",{}).items()
    )
    uc_rows = ""
    for rule in uc.get("rules", []):
        enabled = rule.get("enabled", False)
        eb = '<span class="badge bg">Enabled</span>' if enabled else '<span class="badge br">Disabled</span>'
        tac_str  = ", ".join(rule.get("tactics") or []) or "—"
        tech_lst = rule.get("techniques") or []
        tech_str = ", ".join(tech_lst[:4]) + (f" +{len(tech_lst)-4}" if len(tech_lst)>4 else "")
        sc       = _pri_color(rule.get("severity",""))
        uc_rows += (
            f'<tr><td style="font-weight:600">{_esc(rule.get("name",""))}</td>'
            f'<td><span class="badge bb">{_esc(rule.get("kind",""))}</span></td>'
            f'<td><span style="color:{sc};font-weight:700">{_esc(rule.get("severity",""))}</span></td>'
            f'<td style="font-size:11px">{_esc(tac_str)}</td>'
            f'<td style="font-size:11px">{_esc(tech_str) or "—"}</td>'
            f'<td>{eb}</td>'
            f'<td style="font-size:11px;color:#64748b">{_esc(rule.get("query_frequency","") or "—")}</td>'
            f'<td style="font-size:11px;color:#64748b">{_esc((rule.get("last_modified","") or "")[:10])}</td>'
            f'</tr>'
        )
    uc_err = (
        f'<div style="background:#1c0a0a;border:1px solid #450a0a;border-radius:8px;padding:12px 16px;'
        f'margin-bottom:16px;color:#f87171;font-size:12px">{_esc(uc.get("error",""))}</div>'
    ) if uc.get("error") else ""
    tab4 = (
        uc_err
        + f'<div class="kpi-grid" style="grid-template-columns:repeat(5,1fr)">'
        f'<div class="kpi"><div class="kpi-label">Total</div><div class="kpi-value">{uc_sum.get("total",0)}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Enabled</div><div class="kpi-value" style="color:#22c55e">{uc_sum.get("enabled",0)}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Disabled</div><div class="kpi-value" style="color:#ef4444">{uc_sum.get("disabled",0)}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Enabled %</div><div class="kpi-value">{ena_pct}%</div></div>'
        f'<div class="kpi"><div class="kpi-label">Kinds</div><div class="kpi-value">{len(uc_sum.get("by_kind",{}))}</div></div>'
        f'</div><div style="margin-bottom:12px">{kp}</div>'
        f'<div style="overflow:hidden;border:1px solid var(--border);border-radius:10px"><table>'
        f'<thead><tr><th>Rule Name</th><th>Kind</th><th>Severity</th><th>Tactics</th>'
        f'<th>Techniques</th><th>Status</th><th>Frequency</th><th>Last Modified</th></tr></thead>'
        f'<tbody>{uc_rows or "<tr><td colspan=8 style=color:var(--text-muted);text-align:center;padding:24px>No data</td></tr>"}</tbody>'
        f'</table></div>'
    )

    # ── TAB 5: False Positives ────────────────────────────────────────────────
    max_fp = max((r.get("fp_count",0) for r in fp.get("top_fp_rules",[])), default=1) or 1
    fp_rows = ""
    for r in fp.get("top_fp_rules",[]):
        bw  = round(100 * r.get("fp_count",0) / max_fp)
        sc  = _pri_color(r.get("severity",""))
        fp_rows += (
            f'<tr><td style="font-weight:600">{_esc(r.get("title",""))}</td>'
            f'<td><span style="color:{sc};font-weight:700">{_esc(r.get("severity",""))}</span></td>'
            f'<td><div style="display:flex;align-items:center;gap:6px">'
            f'<div style="width:90px;height:5px;background:#0a1120;border-radius:3px">'
            f'<div style="width:{bw}%;height:5px;background:#ef4444;border-radius:3px"></div></div>'
            f'<span style="color:#ef4444;font-weight:700">{r.get("fp_count",0)}</span></div></td>'
            f'<td style="color:#64748b">{r.get("avg_mttr_hours",0):.1f}h</td></tr>'
        )
    comments_html = ""
    for c in fp.get("fine_tuning_comments",[]):
        clc = "#ef4444" if c.get("classification") == "FalsePositive" else "#f59e0b"
        comments_html += (
            f'<div class="fp-comment" style="border-left-color:{clc}">'
            f'<div style="display:flex;justify-content:space-between;margin-bottom:6px">'
            f'<span style="font-weight:600;color:#e2e8f0">{_esc(c.get("title",""))}</span>'
            f'<div><span class="badge" style="background:{clc}20;color:{clc}">{_esc(c.get("classification",""))}</span>'
            f' <span class="badge" style="background:#1e293b;color:#94a3b8">{_esc(c.get("severity",""))}</span></div></div>'
            f'<p style="color:#94a3b8;font-style:italic;font-size:13px;margin-bottom:6px">'
            f'"{_esc(c.get("comment",""))}"</p>'
            f'<span style="font-size:11px;color:#64748b">#{_esc(c.get("incident_number",""))} · {_esc((c.get("comment_time","") or "")[:10])}</span>'
            f'</div>'
        )
    tab5 = (
        f'<div class="kpi-grid">'
        f'<div class="kpi"><div class="kpi-label">Total (90d)</div><div class="kpi-value">{fp_tot:,}</div></div>'
        f'<div class="kpi"><div class="kpi-label">True Positive</div><div class="kpi-value" style="color:#22c55e">{tp_v}</div></div>'
        f'<div class="kpi"><div class="kpi-label">False Positive</div><div class="kpi-value" style="color:#ef4444">{fp_v}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Benign Positive</div><div class="kpi-value" style="color:#f59e0b">{bp_v}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Undetermined</div><div class="kpi-value" style="color:#64748b">{ud_v}</div></div>'
        f'<div class="kpi"><div class="kpi-label">FP Rate</div><div class="kpi-value" style="color:{"#ef4444" if fp_sum.get("fp_rate",0)>20 else "#f59e0b"}">{fp_sum.get("fp_rate",0):.1f}%</div></div>'
        f'<div class="kpi"><div class="kpi-label">TP Rate</div><div class="kpi-value" style="color:#22c55e">{fp_sum.get("tp_rate",0):.1f}%</div></div>'
        f'</div>'
        f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px">'
        f'<div><h3 style="margin-bottom:10px">Top FP Rules</h3>'
        f'<div style="overflow:hidden;border:1px solid #334155;border-radius:10px"><table>'
        f'<thead><tr><th>Rule</th><th>Severity</th><th>FP Count</th><th>Avg MTTR</th></tr></thead>'
        f'<tbody>{fp_rows or "<tr><td colspan=4 style=color:#64748b;text-align:center;padding:20px>No FP rules</td></tr>"}</tbody>'
        f'</table></div></div>'
        f'<div><h3 style="margin-bottom:10px">Classification Distribution</h3><div class="card">'
        + _bar("True Positive",  tp_v, fp_tot, "#22c55e")
        + _bar("False Positive", fp_v, fp_tot, "#ef4444")
        + _bar("Benign Positive",bp_v, fp_tot, "#f59e0b")
        + _bar("Undetermined",   ud_v, fp_tot, "#64748b")
        + _bar("Unclassified",   uc_v, fp_tot, "#334155")
        + f'</div></div></div>'
        f'<h3 style="margin-bottom:12px">Analyst Fine-Tuning Comments</h3>'
        + (comments_html or '<div class="card" style="color:#64748b;text-align:center;padding:20px">No analyst comments found.</div>')
    )

    # ── TAB 6: Technique Activity ─────────────────────────────────────────────
    max_a = max((t.get("alert_count",0) for t in tech.get("techniques",[])), default=1) or 1
    tech_rows = ""
    for t in tech.get("techniques",[]):
        ta  = t.get("alert_count",0)
        hc  = t.get("high_count",0); mc = t.get("medium_count",0); lc = t.get("low_count",0)
        hw  = round(100*hc/ta) if ta else 0; mw = round(100*mc/ta) if ta else 0; lw = round(100*lc/ta) if ta else 0
        bw2 = round(100*ta/max_a)
        tech_rows += (
            f'<tr><td><code style="color:#93c5fd;background:#1e3a5f;padding:2px 6px;border-radius:3px">{_esc(t.get("id",""))}</code></td>'
            f'<td style="font-size:11px;color:#94a3b8">{_esc(t.get("tactics",""))}</td>'
            f'<td><div style="display:flex;align-items:center;gap:6px">'
            f'<div style="width:70px;height:5px;background:#0a1120;border-radius:3px">'
            f'<div style="width:{bw2}%;height:5px;background:#3b82f6;border-radius:3px"></div></div>'
            f'<span style="font-weight:700">{ta:,}</span></div></td>'
            f'<td><div style="display:flex;height:7px;border-radius:4px;overflow:hidden;width:90px">'
            f'<div style="width:{hw}%;background:#ef4444"></div>'
            f'<div style="width:{mw}%;background:#f59e0b"></div>'
            f'<div style="width:{lw}%;background:#3b82f6"></div>'
            f'</div><span style="font-size:10px;color:var(--text-muted)"> H:{hc} M:{mc} L:{lc}</span></td>'
            f'<td style="text-align:center;color:var(--text-muted)">{t.get("unique_rules",0)}</td>'
            f'<td style="font-size:11px;color:var(--text-muted)">{_esc((t.get("last_seen","") or "")[:10])}</td>'
            f'</tr>'
        )
    tab6 = (
        f'<div style="margin-bottom:14px;font-size:12px;color:var(--text-muted)">Active MITRE techniques from SecurityAlert (last 30 days), ranked by alert volume. Bars show High/Medium/Low severity mix.</div>'
        f'<div style="overflow:hidden;border:1px solid var(--border);border-radius:10px"><table>'
        f'<thead><tr><th>Technique</th><th>Tactic(s)</th><th>Alerts</th><th>Severity Mix</th>'
        f'<th style="text-align:center">Rules Fired</th><th>Last Seen</th></tr></thead>'
        f'<tbody>{tech_rows or "<tr><td colspan=6 style=color:var(--text-muted);text-align:center;padding:24px>No activity in last 30 days.</td></tr>"}</tbody>'
        f'</table></div>'
    )

    # ── TAB 7: Recommended Rules ──────────────────────────────────────────────
    PRI_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rec_sorted = sorted(rec, key=lambda r: PRI_ORDER.get(str(r.get("priority","")).upper(), 4))
    rec_cards = ""
    for rule in rec_sorted:
        pri    = str(rule.get("priority","")).upper()
        pc     = _pri_color(pri)
        effort = rule.get("implementation_effort","")
        ec     = {"Low":"#22c55e","Medium":"#f59e0b","High":"#ef4444"}.get(effort,"#64748b")
        kql    = rule.get("rule_template","") or ""
        kql_block = (
            f'<div class="kql-wrap">'
            f'<div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:0.4px;margin-bottom:6px">KQL Detection Template</div>'
            f'<pre class="kql-block">{_esc(kql)}</pre></div>'
        ) if kql else ""
        rec_cards += (
            f'<div class="rule-card">'
            f'<div class="rule-hdr">'
            f'<span class="rule-pri" style="background:{pc}20;color:{pc};border:1px solid {pc}40">{_esc(pri)}</span>'
            f'<div style="flex:1">'
            f'<div style="font-size:15px;font-weight:700;color:var(--text-primary);margin-bottom:6px">'
            f'{_esc(rule.get("technique_name","") or rule.get("technique",""))}</div>'
            f'<div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center">'
            f'<code style="font-size:10px;color:var(--code-color);background:var(--code-bg);padding:2px 7px;border-radius:4px">'
            f'{_esc(rule.get("technique",""))}</code>'
            f'<span style="font-size:11px;color:var(--text-muted)">Tactic: <strong style="color:var(--text-secondary)">'
            f'{_esc(rule.get("tactic_name","") or rule.get("tactic",""))}</strong></span>'
            f'<span style="font-size:11px;color:var(--text-muted)">Effort: <strong style="color:{ec}">{_esc(effort)}</strong></span>'
            f'<span style="font-size:11px;color:var(--text-muted)">Est. incidents: <strong style="color:var(--text-primary)">'
            f'{rule.get("estimated_incidents",0):,}</strong></span>'
            f'</div></div></div>'
            f'<div class="rule-meta-grid">'
            f'<div><div class="rml">Description</div><div class="rmv">{_esc(rule.get("description",""))}</div></div>'
            f'<div><div class="rml">Detection Method</div><div class="rmv">{_esc(rule.get("detection_method",""))}</div></div>'
            f'<div><div class="rml">Data Source</div><div class="rmv">{_esc(rule.get("mitre_data_source",""))}</div></div>'
            f'</div>'
            f'{kql_block}</div>'
        )
    tab7 = (
        f'<div style="font-size:12px;color:var(--text-muted);margin-bottom:18px">Rules are sorted by priority. '
        f'Each entry includes the KQL detection template ready for implementation in Sentinel.</div>'
        + (rec_cards or '<div class="card" style="color:var(--text-muted);text-align:center;padding:24px">No recommended rules data available.</div>')
    )

    # ── TAB 8: Log Sources ────────────────────────────────────────────────────
    ls_absent  = [s for s in ls if s.get("status") == "ABSENT"]
    ls_partial = [s for s in ls if s.get("status") == "PARTIAL"]
    ls_total_gain = sum(s.get("estimated_coverage_gain", 0) for s in ls)

    def _ls_card(src: dict) -> str:
        pri       = src.get("priority", "")
        pc2       = _pri_color(pri)
        gain      = src.get("estimated_coverage_gain", 0)
        tac_pills = "".join(
            f'<span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;'
            f'font-weight:600;background:#1e293b;color:#94a3b8;margin:2px">{_esc(t)}</span>'
            for t in (src.get("tactics_affected") or [])
        )
        tech_pills = "".join(
            f'<span style="display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;'
            f'font-weight:700;background:#1e3a5f;color:#93c5fd;margin:2px">{_esc(t)}</span>'
            for t in (src.get("techniques_covered") or [])
        )
        impl = src.get("implementation", "")
        impl_block = (
            f'<div style="background:#052e16;border:1px solid #166534;border-radius:6px;'
            f'padding:10px 14px;margin-top:10px;font-size:11px;color:#86efac;line-height:1.6">'
            f'<span style="font-size:10px;text-transform:uppercase;letter-spacing:0.4px;'
            f'color:#4ade80;font-weight:700;display:block;margin-bottom:4px">Implementation</span>'
            f'{_esc(impl)}</div>'
        ) if impl else ""
        return (
            f'<div class="card" style="border-left:3px solid {pc2}">'
            f'<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">'
            f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">'
            f'<span style="font-size:14px;font-weight:700;color:var(--text-primary)">{_esc(src.get("source_name",""))}</span>'
            f'<span style="background:#1e293b;color:#94a3b8;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:600">'
            f'{_esc(src.get("category",""))}</span>'
            f'<span style="background:{pc2}20;color:{pc2};border:1px solid {pc2}40;padding:2px 8px;'
            f'border-radius:999px;font-size:10px;font-weight:700">{_esc(pri)}</span>'
            f'</div>'
            f'<div style="text-align:right;flex-shrink:0;margin-left:12px">'
            f'<div style="font-size:22px;font-weight:800;color:#22c55e">+{gain}%</div>'
            f'<div style="font-size:10px;color:var(--text-muted)">coverage gain</div>'
            f'<div style="font-size:10px;color:var(--text-muted)">{src.get("technique_count",0)} techniques</div>'
            f'</div></div>'
            f'<code style="font-size:10px;color:var(--code-color);background:var(--code-bg);'
            f'padding:3px 8px;border-radius:4px;display:inline-block;margin-bottom:10px">'
            f'{_esc(src.get("sentinel_table",""))}</code>'
            f'<p style="font-size:12px;color:var(--text-secondary);margin-bottom:10px;line-height:1.6">'
            f'{_esc(src.get("description",""))}</p>'
            f'<div style="margin-bottom:6px"><span style="font-size:10px;text-transform:uppercase;'
            f'letter-spacing:0.4px;color:var(--text-muted);font-weight:700;margin-right:6px">TACTICS:</span>'
            f'{tac_pills}</div>'
            f'<div><span style="font-size:10px;text-transform:uppercase;'
            f'letter-spacing:0.4px;color:var(--text-muted);font-weight:700;margin-right:6px">TECHNIQUES:</span>'
            f'{tech_pills}</div>'
            f'{impl_block}</div>'
        )

    def _ls_group(sources: list, label: str, dot_color: str) -> str:
        if not sources:
            return ""
        cards = "".join(_ls_card(s) for s in sources)
        return (
            f'<div style="margin-bottom:24px">'
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;'
            f'padding-bottom:10px;border-bottom:1px solid var(--border)">'
            f'<span style="width:10px;height:10px;border-radius:50%;background:{dot_color};'
            f'flex-shrink:0;display:inline-block"></span>'
            f'<span style="font-size:13px;font-weight:700;color:var(--text-primary)">{_esc(label)}</span>'
            f'<span style="background:{dot_color}20;color:{dot_color};padding:2px 8px;'
            f'border-radius:999px;font-size:10px;font-weight:700">{len(sources)} sources</span>'
            f'</div>{cards}</div>'
        )

    tab8 = (
        f'<div class="kpi-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px">'
        f'<div class="kpi"><div class="kpi-label">Total Assessed</div>'
        f'<div class="kpi-value">{len(ls)}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Absent</div>'
        f'<div class="kpi-value" style="color:#ef4444">{len(ls_absent)}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Partial</div>'
        f'<div class="kpi-value" style="color:#f59e0b">{len(ls_partial)}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Est. Coverage Gain</div>'
        f'<div class="kpi-value" style="color:#22c55e">+{ls_total_gain}%</div></div>'
        f'</div>'
        f'<p style="font-size:12px;color:var(--text-muted);margin-bottom:20px">'
        f'The following log sources are absent or only partially connected to this Sentinel workspace. '
        f'Connecting them would improve MITRE ATT&amp;CK coverage as indicated. Sources are ordered by priority.</p>'
        + _ls_group(ls_absent,  "Absent — Not Connected", "#ef4444")
        + _ls_group(ls_partial, "Partial — Incomplete Coverage", "#f59e0b")
        + ('' if ls else '<div class="card" style="color:var(--text-muted);text-align:center;padding:24px">No log source data available.</div>')
    )

    # ── Final assembly ────────────────────────────────────────────────────────
    return (
        f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>'
        f'<meta name="viewport" content="width=device-width,initial-scale=1"/>'
        f'<title>MITRE ATT&amp;CK Coverage Report</title>'
        f'<style>{css}</style><script>{js}</script></head><body>'
        f'<div class="topbar">'
        f'<div class="topbar-brand">PwC</div>'
        f'<div style="width:1px;height:36px;background:#334155;flex-shrink:0"></div>'
        f'<div><div class="topbar-title">MITRE ATT&amp;CK Coverage Report</div>'
        f'<div class="topbar-sub">Microsoft Sentinel · Sentinel Vigil</div></div>'
        f'<div class="topbar-meta">Generated: {_esc(gen_at)}<br/>'
        f'Coverage: <strong style="color:{cc}">{rp}%</strong> · {len(tactics)} Tactics · {len(rec)} Rec. Rules</div>'
        f'<button id="theme-btn" class="theme-toggle" onclick="toggleTheme()">'
        f'<span class="icon">☀️</span><span class="lbl">Light Mode</span></button>'
        f'</div>'
        f'<div class="tab-nav">'
        f'<button class="tab-btn active" onclick="showTab(\'overview\',this)">Overview</button>'
        f'<button class="tab-btn" onclick="showTab(\'heatmap\',this)">MITRE Heatmap</button>'
        f'<button class="tab-btn" onclick="showTab(\'detail\',this)">Tactic Detail</button>'
        f'<button class="tab-btn" onclick="showTab(\'rules\',this)">Analytics Rules ({uc_sum.get("total",0)})</button>'
        f'<button class="tab-btn" onclick="showTab(\'fp\',this)">False Positives</button>'
        f'<button class="tab-btn" onclick="showTab(\'tech\',this)">Technique Activity</button>'
        f'<button class="tab-btn" onclick="showTab(\'rec\',this)">Recommended Rules ({len(rec)})</button>'
        f'<button class="tab-btn" onclick="showTab(\'logsrc\',this)">Log Sources ({len(ls_absent)} absent)</button>'
        f'</div>'
        f'<div id="t-overview" class="tab-pane active"><h2>Executive Summary</h2>{tab1}</div>'
        f'<div id="t-heatmap"  class="tab-pane"><h2>MITRE ATT&amp;CK Heatmap — Click a Tactic to Expand</h2>{tab2}</div>'
        f'<div id="t-detail"   class="tab-pane"><h2>Technique Detail by Tactic</h2>{tab3}</div>'
        f'<div id="t-rules"    class="tab-pane"><h2>Analytics Rules (Use Cases)</h2>{tab4}</div>'
        f'<div id="t-fp"       class="tab-pane"><h2>False Positive Analysis — Last 90 Days</h2>{tab5}</div>'
        f'<div id="t-tech"     class="tab-pane"><h2>Technique Activity — Last 30 Days</h2>{tab6}</div>'
        f'<div id="t-rec"      class="tab-pane"><h2>Recommended Rules — Implementation Backlog</h2>{tab7}</div>'
        f'<div id="t-logsrc"   class="tab-pane"><h2>Log Sources — Coverage Gap Analysis</h2>{tab8}</div>'
        f'</body></html>'
    )


@router.post("/export-pdf")
async def export_mitre_pdf():
    """Generate and return a PDF version of the full MITRE coverage report."""
    import tempfile
    from convert_html_to_pdf import html_to_pdf

    data     = await _gather_report_data()
    html_str = _build_html_report(data)

    reports_dir = settings.OUTPUT_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    html_path = reports_dir / f"MITRE_ATT_CK_Coverage_Report_{timestamp}.html"
    pdf_path  = html_path.with_suffix(".pdf")
    html_path.write_text(html_str, encoding="utf-8")

    try:
        html_to_pdf(str(html_path), str(pdf_path))
        if not pdf_path.exists() or pdf_path.stat().st_size == 0:
            raise Exception("PDF file is empty or missing after conversion")
        return FileResponse(str(pdf_path), media_type="application/pdf", filename=pdf_path.name)
    except Exception as e:
        logger.error("PDF conversion failed: %s", e)
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=f"PDF conversion failed: {str(e)}")


@router.post("/export-html")
async def export_mitre_html():
    """Generate and return a comprehensive HTML MITRE coverage report with all live data."""
    data     = await _gather_report_data()
    html_str = _build_html_report(data)

    reports_dir = settings.OUTPUT_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = reports_dir / f"MITRE_ATT_CK_Coverage_Report_{timestamp}.html"
    html_path.write_text(html_str, encoding="utf-8")

    logger.info("Exporting full HTML MITRE report: %s", html_path)
    return FileResponse(str(html_path), media_type="text/html", filename=html_path.name)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _parse_list_str(s: str) -> list[str]:
    """Parse '["T1566","T1059"]' or 'InitialAccess,Execution' into a clean list."""
    if not s:
        return []
    try:
        parsed = json.loads(s)
        if isinstance(parsed, list):
            return [str(x).strip() for x in parsed if x]
    except Exception:
        pass
    return [x.strip() for x in re.split(r"[,;]", s) if x.strip()]


# ── Use Cases (Sentinel Management API) ──────────────────────────────────────
@router.get("/use-cases")
async def get_use_cases():
    """
    Fetch all analytics rules directly from the Sentinel management REST API
    (GET /alertRules?api-version=2023-02-01).

    Returns real enabled/disabled status, rule kind, severity, MITRE tactics &
    techniques for every rule configured in the workspace — not just those that
    have fired recently.
    """
    try:
        data = await call_sentinel_mgmt_api_async("/alertRules")
        raw_rules: list = data.get("value", [])
    except Exception as e:
        logger.error("Sentinel alertRules API failed: %s", e)
        return {
            "rules": [],
            "summary": {"total": 0, "enabled": 0, "disabled": 0, "by_kind": {}},
            "by_tactic": {},
            "error": str(e),
        }

    rules = []
    for r in raw_rules:
        props = r.get("properties", {})
        kind  = r.get("kind", "Unknown")

        # "enabled" may be absent on Fusion / ML rules — treat as enabled
        raw_enabled = props.get("enabled")
        enabled = raw_enabled if isinstance(raw_enabled, bool) else True

        # Normalise last-modified timestamp
        last_mod = (
            props.get("lastModifiedUtc")
            or props.get("createdTimeUtc")
            or ""
        )

        rules.append({
            "id":             r.get("name", ""),
            "name":           props.get("displayName") or r.get("name", ""),
            "kind":           kind,
            "enabled":        enabled,
            "severity":       props.get("severity", ""),
            "tactics":        props.get("tactics") or [],
            "techniques":     props.get("techniques") or [],
            "description":    (props.get("description") or "")[:300],
            "last_modified":  last_mod,
            "query_frequency": props.get("queryFrequency", "") or "",
            "template_name":  props.get("alertRuleTemplateName", "") or "",
        })

    # Sort: enabled first, then alphabetically by name
    rules.sort(key=lambda x: (not x["enabled"], x["name"].lower()))

    # Group by tactic for the heatmap-style breakdown
    by_tactic: dict = defaultdict(list)
    for rule in rules:
        for tactic in (rule["tactics"] or ["No Tactic Mapped"]):
            by_tactic[tactic].append(rule)

    kind_counts: dict = defaultdict(int)
    for r in rules:
        kind_counts[r["kind"]] += 1

    return {
        "rules": rules,
        "summary": {
            "total":    len(rules),
            "enabled":  sum(1 for r in rules if r["enabled"]),
            "disabled": sum(1 for r in rules if not r["enabled"]),
            "by_kind":  dict(kind_counts),
        },
        "by_tactic": {
            t: {
                "total":    len(items),
                "enabled":  sum(1 for i in items if i["enabled"]),
                "disabled": sum(1 for i in items if not i["enabled"]),
                "rules":    items,
            }
            for t, items in sorted(by_tactic.items())
        },
    }


# ── False Positives ───────────────────────────────────────────────────────────
@router.get("/false-positives")
async def get_false_positives(days: int = Query(90)):
    """
    FP / BP incident breakdown, top FP-generating rules,
    and fine-tuning comments extracted from analyst incident notes.
    """
    summary_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize
        Total          = count(),
        TruePositive   = countif(Classification =~ "TruePositive"),
        FalsePositive  = countif(Classification =~ "FalsePositive"),
        BenignPositive = countif(Classification =~ "BenignPositive"),
        Undetermined   = countif(Classification =~ "Undetermined"),
        Unclassified   = countif(isempty(Classification) or Classification == "")
    """
    fp_rules_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Classification in ("BenignPositive", "FalsePositive")
    | summarize
        FPCount  = count(),
        AvgMTTR  = round(avg(datetime_diff('hour', ClosedTime, CreatedTime)), 1)
      by Title, Severity
    | sort by FPCount desc
    | limit 25
    """
    comments_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Classification in ("BenignPositive", "FalsePositive")
        and isnotempty(Comments) and Comments != "[]" and Comments != "null"
    | mv-expand Comment = todynamic(Comments)
    | extend CommentText = tostring(Comment.message)
    | where isnotempty(CommentText) and strlen(CommentText) > 15
    | project
        IncidentNumber,
        Title,
        Severity,
        Classification,
        CommentText,
        CommentTime = tostring(Comment.createdTimeUtc)
    | sort by CommentTime desc
    | limit 60
    """

    try:
        summ_rows = (await run_kql(summary_q, days=days)).get("rows", [{}])
        summ = summ_rows[0] if summ_rows else {}
    except Exception as e:
        logger.error("FP summary failed: %s", e)
        summ = {}

    try:
        fp_rows = (await run_kql(fp_rules_q, days=days)).get("rows", [])
    except Exception as e:
        logger.error("FP rules failed: %s", e)
        fp_rows = []

    try:
        comment_rows = (await run_kql(comments_q, days=days)).get("rows", [])
    except Exception as e:
        logger.error("FP comments failed: %s", e)
        comment_rows = []

    total = int(summ.get("Total", 0))
    fp = int(summ.get("FalsePositive", 0))
    bp = int(summ.get("BenignPositive", 0))
    tp = int(summ.get("TruePositive", 0))

    return {
        "summary": {
            "total": total,
            "true_positive": tp,
            "false_positive": fp,
            "benign_positive": bp,
            "undetermined": int(summ.get("Undetermined", 0)),
            "unclassified": int(summ.get("Unclassified", 0)),
            "fp_rate": round(100.0 * (fp + bp) / total, 1) if total > 0 else 0.0,
            "tp_rate": round(100.0 * tp / total, 1) if total > 0 else 0.0,
        },
        "top_fp_rules": [
            {
                "title": r.get("Title", "Unknown"),
                "severity": r.get("Severity", "Unknown"),
                "fp_count": int(r.get("FPCount", 0)),
                "avg_mttr_hours": float(r.get("AvgMTTR", 0) or 0),
            }
            for r in fp_rows
        ],
        "fine_tuning_comments": [
            {
                "incident_number": str(r.get("IncidentNumber", "")),
                "title": r.get("Title", ""),
                "severity": r.get("Severity", ""),
                "classification": r.get("Classification", ""),
                "comment": r.get("CommentText", ""),
                "comment_time": r.get("CommentTime", "") or "",
            }
            for r in comment_rows
        ],
    }


# ── Technique Activity ────────────────────────────────────────────────────────
@router.get("/technique-activity")
async def get_technique_activity(days: int = Query(30)):
    """Real alert counts per MITRE technique from SecurityAlert (mv-expand)."""
    q = f"""
    SecurityAlert
    | where TimeGenerated > ago({days}d)
    | where isnotempty(AttackTechniques)
    | mv-expand Technique = todynamic(AttackTechniques)
    | where isnotempty(tostring(Technique))
    | summarize
        AlertCount   = count(),
        UniqueRules  = dcount(AlertName),
        HighCount    = countif(AlertSeverity =~ "High"),
        MediumCount  = countif(AlertSeverity =~ "Medium"),
        LowCount     = countif(AlertSeverity =~ "Low"),
        LastSeen     = max(TimeGenerated)
      by TechniqueId = tostring(Technique), Tactics
    | sort by AlertCount desc
    | limit 30
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "techniques": [
                {
                    "id": r.get("TechniqueId", ""),
                    "tactics": r.get("Tactics", ""),
                    "alert_count": int(r.get("AlertCount", 0)),
                    "unique_rules": int(r.get("UniqueRules", 0)),
                    "high_count": int(r.get("HighCount", 0)),
                    "medium_count": int(r.get("MediumCount", 0)),
                    "low_count": int(r.get("LowCount", 0)),
                    "last_seen": r.get("LastSeen", "") or "",
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Technique activity failed: %s", e)
        return {"techniques": [], "error": str(e)}
