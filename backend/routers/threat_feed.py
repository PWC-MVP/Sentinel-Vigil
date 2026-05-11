import asyncio
import json
import re
import time
import logging
import datetime

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import httpx

from backend.services.llm import complete, stream_complete
from backend.services.sentinel import run_kql

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threat-feed", tags=["threat-feed"])

_cache: dict = {}
CACHE_TTL = 1800  # 30 minutes


def _cached(key: str):
    entry = _cache.get(key)
    if entry and (time.time() - entry["ts"]) < CACHE_TTL:
        return entry["data"]
    return None


def _store(key: str, data):
    _cache[key] = {"ts": time.time(), "data": data}
    return data


def _clean_html(html: str) -> str:
    clean = re.sub(r"<[^>]+>", "", html or "")
    clean = re.sub(r"&\w+;", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:500]


def _guess_category(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["ransomware", "ransom"]):
        return "Ransomware"
    if any(k in t for k in ["phishing", "phish", "social engineer"]):
        return "Phishing"
    if any(k in t for k in ["vulnerability", "cve", "patch", "zero-day", "0-day", "exploit"]):
        return "Vulnerability"
    if any(k in t for k in ["data breach", "data leak", "exposed data", "stolen", "leaked"]):
        return "Data Breach"
    if any(k in t for k in ["apt", "nation-state", "espionage", "state-sponsored"]):
        return "APT"
    if any(k in t for k in ["malware", "trojan", "botnet", "backdoor", "infostealer"]):
        return "Malware"
    if any(k in t for k in ["supply chain", "software supply", "open source"]):
        return "Supply Chain"
    if any(k in t for k in ["ddos", "denial of service"]):
        return "DDoS"
    if any(k in t for k in ["cloud", "aws", "azure", "gcp", "kubernetes"]):
        return "Cloud"
    if any(k in t for k in ["artificial intelligence", " llm", "deepfake", "ai-powered"]):
        return "AI Security"
    return "General"


RSS_FEEDS = [
    # News & Journalism
    ("The Hacker News",        "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer",       "https://www.bleepingcomputer.com/feed/"),
    ("Dark Reading",           "https://www.darkreading.com/rss.xml"),
    ("Krebs on Security",      "https://krebsonsecurity.com/feed/"),
    ("Threatpost",             "https://threatpost.com/feed/"),
    ("Schneier on Security",   "https://www.schneier.com/feed/atom/"),
    # Government / Standards
    ("CISA Alerts",            "https://www.cisa.gov/uscert/ncas/alerts.xml"),
    ("US-CERT Activity",       "https://www.cisa.gov/uscert/ncas/current-activity.xml"),
    ("NIST Cybersecurity",     "https://www.nist.gov/blogs/cybersecurity-insights/rss.xml"),
    # Vendor Research
    ("Microsoft Security",     "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Palo Alto Unit42",       "https://unit42.paloaltonetworks.com/feed/"),
    ("CrowdStrike Blog",       "https://www.crowdstrike.com/blog/feed/"),
    ("Mandiant Blog",          "https://www.mandiant.com/resources/blog/rss.xml"),
    ("Securelist (Kaspersky)", "https://securelist.com/feed/"),
    ("ESET WeLiveSecurity",    "https://www.welivesecurity.com/en/feed/"),
    ("Malwarebytes Blog",      "https://www.malwarebytes.com/blog/feed/"),
    ("Check Point Research",   "https://research.checkpoint.com/feed/"),
    ("SentinelOne Blog",       "https://www.sentinelone.com/blog/feed/"),
    ("Rapid7 Blog",            "https://blog.rapid7.com/rss/"),
    ("Recorded Future Blog",   "https://www.recordedfuture.com/feed"),
    # Deep Research
    ("Google Project Zero",    "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("SANS ISC",               "https://isc.sans.edu/rssfeed.xml"),
]

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ── News feed helpers ─────────────────────────────────────────────────────────

async def _fetch_feed(client: httpx.AsyncClient, source: str, url: str, feedparser) -> list:
    try:
        resp = await client.get(url)
        feed = feedparser.parse(resp.text)
        articles = []
        for entry in feed.entries[:8]:
            tags = []
            if hasattr(entry, "tags"):
                tags = [t.get("term", "") for t in entry.tags[:4] if t.get("term")]
            pub_date = (
                entry.get("published") or entry.get("updated") or entry.get("created") or ""
            )
            summary = _clean_html(entry.get("summary") or entry.get("description") or "")
            articles.append({
                "id": entry.get("id") or entry.get("link", ""),
                "title": entry.get("title", "Untitled"),
                "summary": summary,
                "link": entry.get("link", ""),
                "source": source,
                "published": pub_date,
                "tags": tags,
                "category": _guess_category(
                    entry.get("title", "") + " " + (entry.get("summary") or "")
                ),
            })
        return articles
    except Exception as e:
        logger.warning(f"Threat feed: failed to fetch {source}: {e}")
        return []


@router.get("/news")
async def get_news():
    cached = _cached("news")
    if cached:
        return cached

    try:
        import feedparser
    except ImportError:
        return _store("news", {"articles": [], "count": 0,
                               "error": "feedparser not installed — run: pip install feedparser"})

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        results = await asyncio.gather(
            *[_fetch_feed(client, source, url, feedparser) for source, url in RSS_FEEDS],
            return_exceptions=True,
        )

    articles = []
    for r in results:
        if isinstance(r, list):
            articles.extend(r)

    result = {"articles": articles, "count": len(articles)}
    return _store("news", result)


@router.get("/cves")
async def get_cves():
    cached = _cached("cves")
    if cached:
        return cached

    cves = []

    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        try:
            resp = await client.get(CISA_KEV_URL)
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            for v in reversed(vulns[-30:]):
                cves.append({
                    "id": v.get("cveID", ""),
                    "title": v.get("vulnerabilityName", ""),
                    "description": v.get("shortDescription", ""),
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "date_added": v.get("dateAdded", ""),
                    "due_date": v.get("dueDate", ""),
                    "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "source": "CISA KEV",
                    "severity": "Critical",
                    "score": None,
                    "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "nvd_link": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID', '')}",
                })
        except Exception as e:
            logger.warning(f"CISA KEV fetch failed: {e}")

        try:
            resp = await client.get(NVD_URL, params={"resultsPerPage": 20, "cvssV3Severity": "CRITICAL"})
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if any(c["id"] == cve_id for c in cves):
                    continue
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                score = None
                severity = "Critical"
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if key in metrics and metrics[key]:
                        cvss = metrics[key][0].get("cvssData", {})
                        score = cvss.get("baseScore")
                        severity = cvss.get("baseSeverity", "Critical")
                        break
                published = cve.get("published", "")
                cves.append({
                    "id": cve_id,
                    "title": cve_id,
                    "description": desc[:400],
                    "vendor": "",
                    "product": "",
                    "date_added": published[:10] if published else "",
                    "due_date": "",
                    "ransomware_use": "Unknown",
                    "source": "NVD",
                    "severity": severity,
                    "score": score,
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "nvd_link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
        except Exception as e:
            logger.warning(f"NVD fetch failed: {e}")

    result = {"cves": cves, "count": len(cves)}
    return _store("cves", result)


@router.post("/refresh")
async def refresh_cache():
    _cache.clear()
    return {"status": "cache cleared"}


# ── Threat Investigation (SSE streaming) ─────────────────────────────────────

def _sse(event_type: str, data: dict) -> str:
    return f"data: {json.dumps({'type': event_type, **data})}\n\n"


async def _fetch_article_text(url: str) -> str:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            html = resp.text
            html = re.sub(
                r"<(script|style|nav|footer|header|aside|iframe|noscript)[^>]*>.*?</\1>",
                "", html, flags=re.DOTALL | re.IGNORECASE,
            )
            text = re.sub(r"<[^>]+>", " ", html)
            text = re.sub(r"&[a-zA-Z]+;", " ", text)
            text = re.sub(r"&#\d+;", " ", text)
            text = re.sub(r"\s+", " ", text).strip()
            return text[:8000]
    except Exception as e:
        return f"[Article content unavailable: {e}]"


async def _investigate_stream(payload: dict):
    title    = payload.get("title", "Unknown Threat")
    link     = payload.get("link", "")
    summary  = payload.get("summary", "")
    source   = payload.get("source", "")
    category = payload.get("category", "General")
    now      = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    try:
        # ── Step 1: Fetch article ─────────────────────────────────────────────
        yield _sse("status", {"step": "fetch", "msg": f"Fetching article content from {source}…"})
        article_text = await _fetch_article_text(link)
        yield _sse("status", {"step": "fetch_done", "msg": "Article fetched. Sending to ARIA for analysis…"})

        # ── Step 2: LLM analysis + KQL query generation ───────────────────────
        yield _sse("status", {"step": "analyze", "msg": "ARIA is analysing the threat and generating detection queries…"})

        analysis_prompt = f"""You are analysing a cybersecurity article to investigate the described threat in a Microsoft Sentinel / Azure Log Analytics workspace.

Article Title: {title}
Source: {source}
Category: {category}
Summary: {summary}

Article Content:
{article_text}

Respond with ONLY a valid JSON object. No markdown, no code fences, no explanation:
{{
  "threat_summary": "3-4 sentence precise technical description of the threat",
  "threat_actor": "threat actor name or Unknown",
  "targeted_sectors": ["industry sectors targeted"],
  "affected_systems": ["specific platforms, OS, applications affected"],
  "iocs": {{
    "ips": ["suspicious IPs mentioned"],
    "domains": ["suspicious domains or URLs mentioned"],
    "hashes": ["file hashes mentioned"],
    "cves": ["CVE IDs mentioned"]
  }},
  "mitre_techniques": [
    {{"id": "TXXXX", "name": "technique name", "tactic": "tactic category"}}
  ],
  "risk_level": "Critical|High|Medium|Low",
  "kql_queries": [
    {{
      "title": "short descriptive title",
      "description": "what this query detects",
      "query": "complete valid KQL query against common Sentinel tables: SecurityAlert, SigninLogs, SecurityEvent, DeviceProcessEvents, DeviceNetworkEvents, CommonSecurityLog, AuditLogs, OfficeActivity, ThreatIntelligenceIndicator, etc.",
      "severity": "High|Medium|Low"
    }}
  ]
}}

Generate 4-5 actionable KQL queries that would detect signs of this specific threat. Use realistic Sentinel table names and field names. Make queries practical — they should run without modification."""

        analysis_raw = await complete(
            system="You are a cybersecurity analyst. Always respond with valid JSON only. No markdown. No code fences.",
            user_msg=analysis_prompt,
        )

        raw = analysis_raw["text"].strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        analysis = json.loads(raw)

        kql_queries = analysis.get("kql_queries", [])
        yield _sse("analysis", {
            "threat_summary":    analysis.get("threat_summary", ""),
            "threat_actor":      analysis.get("threat_actor", "Unknown"),
            "targeted_sectors":  analysis.get("targeted_sectors", []),
            "affected_systems":  analysis.get("affected_systems", []),
            "iocs":              analysis.get("iocs", {}),
            "mitre_techniques":  analysis.get("mitre_techniques", []),
            "risk_level":        analysis.get("risk_level", "Medium"),
            "kql_count":         len(kql_queries),
            "kql_queries":       [{"title": q["title"], "description": q["description"],
                                   "severity": q["severity"]} for q in kql_queries],
        })

        # ── Step 3: Run KQL queries (with LLM self-correction on failure) ───────
        yield _sse("status", {"step": "kql", "msg": f"Running {len(kql_queries)} detection queries against your workspace…"})

        MAX_KQL_RETRIES = 2
        kql_results = []

        for i, q in enumerate(kql_queries):
            current_query = q["query"]
            last_error: str = ""
            succeeded = False

            for attempt in range(MAX_KQL_RETRIES + 1):
                yield _sse("kql_running", {
                    "index": i, "title": q["title"],
                    "query": current_query, "attempt": attempt,
                })
                try:
                    res = await run_kql(current_query, days=30)
                    kql_results.append({
                        "title":       q["title"],
                        "description": q.get("description", ""),
                        "severity":    q.get("severity", "Medium"),
                        "query":       current_query,
                        "row_count":   res.get("row_count", 0),
                        "columns":     res.get("columns", []),
                        "rows":        res.get("rows", [])[:20],
                        "status":      "success",
                        "attempts":    attempt + 1,
                    })
                    yield _sse("kql_result", {
                        "index": i, "title": q["title"],
                        "row_count": res.get("row_count", 0),
                        "status": "success", "attempts": attempt + 1,
                    })
                    succeeded = True
                    break

                except Exception as e:
                    last_error = str(e)

                    if attempt >= MAX_KQL_RETRIES:
                        break  # exhausted retries

                    # Ask LLM to fix the broken query
                    yield _sse("kql_retrying", {
                        "index": i, "title": q["title"],
                        "attempt": attempt + 1, "error": last_error,
                    })
                    try:
                        fix = await complete(
                            system=(
                                "You are a Microsoft Sentinel KQL expert. "
                                "Fix the broken Kusto query and return ONLY the corrected KQL. "
                                "No explanation. No markdown. No code fences. Just the raw query."
                            ),
                            user_msg=(
                                f"This KQL query failed with the error below. "
                                f"Fix it so it runs successfully in Azure Log Analytics / Microsoft Sentinel.\n\n"
                                f"Original query:\n{current_query}\n\n"
                                f"Error:\n{last_error}\n\n"
                                f"Return ONLY the corrected KQL query."
                            ),
                        )
                        fixed = fix["text"].strip()
                        fixed = re.sub(r"^```(?:kql|kusto)?\s*", "", fixed)
                        fixed = re.sub(r"\s*```$", "", fixed)
                        current_query = fixed.strip()
                    except Exception as fix_err:
                        logger.warning("KQL auto-fix LLM call failed: %s", fix_err)
                        break  # can't fix, give up

            if not succeeded:
                kql_results.append({
                    "title":       q["title"],
                    "description": q.get("description", ""),
                    "severity":    q.get("severity", "Medium"),
                    "query":       current_query,
                    "row_count":   0,
                    "columns":     [],
                    "rows":        [],
                    "status":      "error",
                    "error":       last_error,
                    "attempts":    MAX_KQL_RETRIES + 1,
                })
                yield _sse("kql_result", {
                    "index": i, "title": q["title"],
                    "row_count": 0, "status": "error",
                    "error": last_error, "attempts": MAX_KQL_RETRIES + 1,
                })

        # ── Step 4: Generate HTML report ──────────────────────────────────────
        yield _sse("status", {"step": "report", "msg": "Generating investigation report…"})

        total_hits     = sum(r.get("row_count", 0) for r in kql_results if r["status"] == "success")
        queries_w_hits = [r for r in kql_results if r.get("row_count", 0) > 0]

        kql_detail = ""
        for r in kql_results:
            kql_detail += f"\n### {r['title']} — Severity: {r['severity']}\n"
            kql_detail += f"Description: {r['description']}\n"
            kql_detail += f"Query:\n```kql\n{r['query']}\n```\n"
            if r["status"] == "error":
                kql_detail += f"Result: Error — {r.get('error', 'Unknown error')}\n"
            else:
                kql_detail += f"Result: **{r['row_count']} matching records**\n"
                if r["rows"]:
                    cols = r["columns"][:6]
                    kql_detail += "| " + " | ".join(cols) + " |\n"
                    kql_detail += "| " + " | ".join(["---"] * len(cols)) + " |\n"
                    for row in r["rows"][:5]:
                        kql_detail += "| " + " | ".join(str(row.get(c, ""))[:60] for c in cols) + " |\n"
            kql_detail += "\n"

        iocs = analysis.get("iocs", {})
        mitre = analysis.get("mitre_techniques", [])

        report_prompt = f"""Generate a complete, self-contained professional cybersecurity HTML investigation report.

# Source
Title: {title}
Source: {source}
Link: {link}
Generated: {now}

# Threat Analysis
Summary: {analysis.get('threat_summary', '')}
Threat Actor: {analysis.get('threat_actor', 'Unknown')}
Risk Level: {analysis.get('risk_level', 'Medium')}
Targeted Sectors: {', '.join(analysis.get('targeted_sectors', [])) or 'Unknown'}
Affected Systems: {', '.join(analysis.get('affected_systems', [])) or 'Unknown'}

# IOCs
IPs: {', '.join(iocs.get('ips', [])) or 'None identified'}
Domains: {', '.join(iocs.get('domains', [])) or 'None identified'}
File Hashes: {', '.join(iocs.get('hashes', [])) or 'None identified'}
CVEs: {', '.join(iocs.get('cves', [])) or 'None identified'}

# MITRE ATT&CK Techniques
{json.dumps(mitre, indent=2)}

# Detection Results
Total queries run: {len(kql_results)}
Queries with hits: {len(queries_w_hits)}
Total records matched: {total_hits}

{kql_detail}

Generate a COMPLETE valid HTML document with ALL of the following:

1. <!DOCTYPE html><html><head> with embedded <style> block — light professional theme:
   body background #f8f9fa, cards #ffffff, borders #dee2e6, text #212529,
   headings #1a1a2e, accent orange #d04a02, links #d04a02,
   section headers with a left orange border-left: 4px solid #d04a02
2. A professional header with white background, "Sentinel Vigil — Vigil Threat Reporter" title in dark color, article title as subtitle, source badge, timestamp
3. Risk badge (color-coded: Critical=#dc3545, High=#fd7e14, Medium=#ffc107 with dark text, Low=#198754)
4. Executive Summary section on white card with light shadow
5. Threat Details table (actor, sectors, affected systems, risk level)
6. IOCs table with type and value columns — highlight if empty
7. MITRE ATT&CK table with ID, name, tactic columns — link IDs to attack.mitre.org, technique IDs styled in orange
8. Detection Results section: for each KQL query show title, severity badge, query in <pre><code> with light grey background (#f4f4f4) and dark text, result count badge, and if rows > 0 a data table with sample results
9. Overall Risk Assessment paragraph synthesising all detection results
10. Recommended Actions numbered list (specific, prioritised, actionable)
11. Footer with light grey background, "Generated by ARIA · Sentinel Vigil · {now}" and source link

Style requirements:
- All CSS in <style> block in <head>, no external CDN
- body font: system-ui, -apple-system, sans-serif
- Cards: background #fff, border-radius: 8px, box-shadow: 0 1px 4px rgba(0,0,0,0.08), border: 1px solid #dee2e6, padding: 24px, margin-bottom: 20px
- Tables: thead background #f1f3f5, striped rows (#f8f9fa on even rows), border: 1px solid #dee2e6
- Severity badges: pill-shaped, colored backgrounds with matching text
- KQL code blocks: background #f4f4f4, border: 1px solid #e0e0e0, color #333, border-radius: 6px, padding: 12px
- Print-friendly (no fixed positioning)
- No JavaScript required
- Max content width: 960px, centered with auto margins"""

        report_chunks: list[str] = []
        async for chunk in stream_complete(
            system="You are a cybersecurity report generator. Output ONLY valid complete HTML with a light white/grey background theme. No markdown. No code fences. Start with <!DOCTYPE html>.",
            user_msg=report_prompt,
        ):
            if chunk["type"] == "text":
                report_chunks.append(chunk["text"])
                yield _sse("report_chunk", {"text": chunk["text"]})

        report_html = "".join(report_chunks).strip()
        report_html = re.sub(r"^```html\s*", "", report_html)
        report_html = re.sub(r"\s*```$", "", report_html)

        yield _sse("done", {
            "report_html": report_html,
            "total_hits":  total_hits,
        })

    except Exception as e:
        logger.error("Investigation stream error: %s", e, exc_info=True)
        yield _sse("error", {"msg": str(e)})


@router.post("/investigate")
async def investigate_threat(payload: dict):
    return StreamingResponse(
        _investigate_stream(payload),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
