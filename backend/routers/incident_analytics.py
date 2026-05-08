from collections import defaultdict
from fastapi import APIRouter, HTTPException, Query, Body
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from backend.services.sentinel import run_kql
from backend.services import llm as llm_service
import logging
import json as _json_g
import re as _re_g

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incident-analytics", tags=["incident-analytics"])


class LlmAssessmentRequest(BaseModel):
    days: int = 30
    summary: dict = {}
    mttr: dict = {}
    sla: list[dict] = []
    owners: list[dict] = []
    trends: list[dict] = []
    recurrence: list[dict] = []


class EmailReportRequest(BaseModel):
    days: int = 30
    to: list[str] = []
    app_url: str = ""
    include_enrichment: bool = True
    include_llm: bool = True
    incident_numbers: list[int] = []  # empty = all active
    max_incidents: int = 200


@router.get("/mttr")
async def get_mttr(days: float = Query(30)):
    """Mean / median / P90 / P95 time-to-resolve metrics, overall and by severity."""
    overall_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status =~ "Closed"
        and isnotempty(ClosedTime) and isnotempty(CreatedTime)
    | extend MTTR_Hours = datetime_diff('hour', ClosedTime, CreatedTime)
    | where MTTR_Hours >= 0 and MTTR_Hours < 8760
    | summarize
        AvgMTTR    = round(avg(MTTR_Hours),            1),
        MedianMTTR = round(percentile(MTTR_Hours, 50), 1),
        P90MTTR    = round(percentile(MTTR_Hours, 90), 1),
        P95MTTR    = round(percentile(MTTR_Hours, 95), 1),
        MinMTTR    = min(MTTR_Hours),
        MaxMTTR    = max(MTTR_Hours),
        TotalClosed= count()
    """
    sev_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status =~ "Closed"
        and isnotempty(ClosedTime) and isnotempty(CreatedTime)
    | extend MTTR_Hours = datetime_diff('hour', ClosedTime, CreatedTime)
    | where MTTR_Hours >= 0 and MTTR_Hours < 8760
    | summarize
        AvgMTTR = round(avg(MTTR_Hours), 1),
        Count   = count()
      by Severity
    | sort by AvgMTTR asc
    """

    try:
        r = ((await run_kql(overall_q, days=days)).get("rows", [{}]) or [{}])[0]
    except Exception as e:
        logger.error("MTTR overall failed: %s", e)
        r = {}

    try:
        sev_rows = (await run_kql(sev_q, days=days)).get("rows", [])
    except Exception:
        sev_rows = []

    return {
        "avg_hours": float(r.get("AvgMTTR", 0)),
        "median_hours": float(r.get("MedianMTTR", 0)),
        "p90_hours": float(r.get("P90MTTR", 0)),
        "p95_hours": float(r.get("P95MTTR", 0)),
        "min_hours": float(r.get("MinMTTR", 0)),
        "max_hours": float(r.get("MaxMTTR", 0)),
        "total_closed": int(r.get("TotalClosed", 0)),
        "by_severity": [
            {
                "severity": row.get("Severity", "Unknown"),
                "avg_hours": float(row.get("AvgMTTR", 0)),
                "count": int(row.get("Count", 0)),
            }
            for row in sev_rows
        ],
    }


@router.get("/trends")
async def get_incident_trends(days: float = Query(30)):
    """Daily incident creation counts by severity."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize Count = count()
        by bin(CreatedTime, 1d), Severity
    | sort by CreatedTime asc
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        by_date: dict = defaultdict(lambda: {"High": 0, "Medium": 0, "Low": 0, "Informational": 0})
        for r in rows:
            date = (r.get("CreatedTime") or "")[:10]
            sev = r.get("Severity", "Informational")
            if sev in by_date[date]:
                by_date[date][sev] += int(r.get("Count", 0))
        return {"daily": [{"date": d, **c} for d, c in sorted(by_date.items())]}
    except Exception as e:
        logger.error("Trends query failed: %s", e)
        return {"daily": [], "error": str(e)}


@router.get("/owners")
async def get_incident_owners(days: float = Query(30)):
    """Incident distribution by assigned owner."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | extend OwnerName = iff(
        isempty(Owner) or Owner == "null" or Owner == "{{}}",
        "Unassigned",
        coalesce(
            tostring(todynamic(Owner).userPrincipalName),
            tostring(todynamic(Owner).assignedTo),
            "Unassigned"
        )
      )
    | extend OwnerName = iff(OwnerName == "null" or OwnerName == "", "Unassigned", OwnerName)
    | summarize
        Total  = count(),
        Open   = countif(Status in ("Active", "New")),
        Closed = countif(Status =~ "Closed")
      by OwnerName
    | sort by Total desc
    | limit 15
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "owners": [
                {
                    "name": r.get("OwnerName", "Unknown"),
                    "total": int(r.get("Total", 0)),
                    "open": int(r.get("Open", 0)),
                    "closed": int(r.get("Closed", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Owners query failed: %s", e)
        return {"owners": [], "error": str(e)}


@router.get("/sla")
async def get_sla_compliance(days: float = Query(30)):
    """SLA compliance per severity tier (High=4h, Medium=8h, Low=24h, Info=72h)."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status =~ "Closed" and isnotempty(ClosedTime)
    | extend MTTR_Hours = datetime_diff('hour', ClosedTime, CreatedTime)
    | extend SLATarget = case(
        Severity =~ "High",          4,
        Severity =~ "Medium",        8,
        Severity =~ "Low",          24,
        72
    )
    | extend SLAMet = MTTR_Hours <= SLATarget
    | summarize
        Total          = count(),
        SLAMet         = countif(SLAMet),
        SLABreached    = countif(not(SLAMet)),
        AvgMTTR        = round(avg(MTTR_Hours), 1)
      by Severity, SLATarget
    | extend ComplianceRate = round(100.0 * SLAMet / Total, 1)
    | sort by SLATarget asc
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "sla": [
                {
                    "severity": r.get("Severity", "Unknown"),
                    "sla_target_hours": int(r.get("SLATarget", 0)),
                    "total": int(r.get("Total", 0)),
                    "sla_met": int(r.get("SLAMet", 0)),
                    "sla_breached": int(r.get("SLABreached", 0)),
                    "compliance_rate": float(r.get("ComplianceRate", 0)),
                    "avg_mttr": float(r.get("AvgMTTR", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("SLA query failed: %s", e)
        return {"sla": [], "error": str(e)}


@router.get("/summary")
async def get_incident_summary(days: float = Query(30)):
    """Quick counts for the stat tile row."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize
        Total         = count(),
        Open          = countif(Status in ("Active", "New")),
        Closed        = countif(Status =~ "Closed"),
        HighCount     = countif(Severity =~ "High"),
        AvgFirstResp  = round(avg(
            datetime_diff('hour', FirstActivityTime, CreatedTime)
        ), 1)
    """
    try:
        r = ((await run_kql(q, days=days)).get("rows", [{}]) or [{}])[0]
        return {
            "total": int(r.get("Total", 0)),
            "open": int(r.get("Open", 0)),
            "closed": int(r.get("Closed", 0)),
            "high_count": int(r.get("HighCount", 0)),
            "avg_first_resp_hours": float(r.get("AvgFirstResp", 0)),
        }
    except Exception as e:
        logger.error("Incident summary failed: %s", e)
        return {"total": 0, "open": 0, "closed": 0, "high_count": 0, "avg_first_resp_hours": 0}


@router.get("/incidents")
async def get_incidents(days: float = Query(30)):
    """Full incident list with all details, limit 300, sorted newest first."""
    # column_ifexists guards against workspaces that don't carry every optional
    # field.  Tactics is left as raw dynamic — Python normalises it below.
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | extend OwnerName = iff(
        isempty(Owner) or Owner == "null" or Owner == "{{}}",
        "Unassigned",
        coalesce(
            tostring(todynamic(Owner).userPrincipalName),
            tostring(todynamic(Owner).assignedTo),
            "Unassigned"
        )
      )
    | extend OwnerName = iff(OwnerName == "null" or OwnerName == "", "Unassigned", OwnerName)
    | extend MTTR_Hours = iff(
        Status =~ "Closed" and isnotempty(ClosedTime),
        toreal(datetime_diff('hour', ClosedTime, CreatedTime)),
        toreal(datetime_diff('hour', now(), CreatedTime))
      )
    | project
        IncidentNumber,
        Title,
        Severity,
        Status,
        OwnerName,
        CreatedTime,
        ClosedTime,
        LastUpdated           = TimeGenerated,
        Classification        = tostring(column_ifexists("Classification", "")),
        ClassificationComment = tostring(column_ifexists("ClassificationComment", "")),
        MTTR_Hours,
        Tactics               = column_ifexists("Tactics", dynamic(null)),
        Description           = tostring(column_ifexists("Description", ""))
    | sort by CreatedTime desc
    | limit 300
    """

    def _tactics(raw) -> str:
        """Normalise Tactics from dynamic array, list, or string to a display string."""
        if raw is None or raw == "":
            return ""
        if isinstance(raw, list):
            return ", ".join(str(t) for t in raw if t)
        s = str(raw).strip()
        if s.startswith("["):
            import json as _json
            try:
                arr = _json.loads(s)
                if isinstance(arr, list):
                    return ", ".join(str(t) for t in arr if t)
            except Exception:
                pass
        return s

    def _row(r: dict) -> dict:
        try:
            mttr = round(float(r.get("MTTR_Hours") or 0), 1)
        except (TypeError, ValueError):
            mttr = 0.0
        return {
            "number":                 r.get("IncidentNumber", ""),
            "title":                  r.get("Title", ""),
            "severity":               r.get("Severity", "Unknown"),
            "status":                 r.get("Status", "Unknown"),
            "owner":                  r.get("OwnerName", "Unassigned"),
            "created":                r.get("CreatedTime", ""),
            "closed":                 r.get("ClosedTime", "") or "",
            "last_updated":           r.get("LastUpdated", ""),
            "classification":         r.get("Classification", "") or "",
            "classification_comment": r.get("ClassificationComment", "") or "",
            "mttr_hours":             mttr,
            "tactics":                _tactics(r.get("Tactics")),
            "description":            r.get("Description", "") or "",
        }

    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {"incidents": [_row(r) for r in rows]}
    except Exception as e:
        logger.error("Incidents list failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Incidents query failed: {e}")


@router.get("/recurrence")
async def get_recurrence(days: float = Query(30)):
    """Incidents that repeat with the same title — possible detection signal fatigue."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize
        Count          = count(),
        LastSeen       = max(CreatedTime),
        FirstSeen      = min(CreatedTime),
        AvgMTTR        = round(avg(iff(
            Status =~ "Closed" and isnotempty(ClosedTime),
            toreal(datetime_diff('hour', ClosedTime, CreatedTime)),
            toreal(-1)
        )), 1),
        Severities     = make_set(Severity),
        OpenCount      = countif(Status in ("Active", "New"))
      by Title
    | where Count > 1
    | sort by Count desc
    | limit 30
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "recurrent": [
                {
                    "title":       r.get("Title", ""),
                    "count":       int(r.get("Count", 0)),
                    "last_seen":   r.get("LastSeen", ""),
                    "first_seen":  r.get("FirstSeen", ""),
                    "avg_mttr":    float(r.get("AvgMTTR", -1)),
                    "severities":  r.get("Severities", []),
                    "open_count":  int(r.get("OpenCount", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Recurrence query failed: %s", e)
        return {"recurrent": [], "error": str(e)}


@router.post("/llm-assessment")
async def get_llm_assessment(req: LlmAssessmentRequest):
    """Generate an LLM SOC assessment based on the current incident analytics stats."""
    # Build context from all stats
    sla_lines = "\n".join(
        f"  - {s.get('severity','?')}: {s.get('compliance_rate',0)}% compliance, "
        f"avg MTTR {s.get('avg_mttr',0):.1f}h (SLA target {s.get('sla_target_hours',0)}h), "
        f"{s.get('sla_breached',0)} breached"
        for s in req.sla
    ) or "  No SLA data available"

    owner_lines = "\n".join(
        f"  - {o.get('name','?')}: {o.get('total',0)} total, {o.get('open',0)} open, {o.get('closed',0)} closed"
        for o in req.owners[:10]
    ) or "  No owner data available"

    recurrence_lines = "\n".join(
        f"  - \"{r.get('title','?')}\": {r.get('count',0)} occurrences, {r.get('open_count',0)} still open"
        for r in req.recurrence[:8]
    ) or "  No recurring incidents detected"

    total_trend = sum(d.get('High', 0) + d.get('Medium', 0) + d.get('Low', 0) + d.get('Informational', 0)
                      for d in req.trends)

    context = f"""Incident Analytics Assessment — Last {req.days} days

SUMMARY
  Total Incidents: {req.summary.get('total', 0)}
  Open: {req.summary.get('open', 0)} | Closed: {req.summary.get('closed', 0)}
  High Severity: {req.summary.get('high_count', 0)}
  Avg First Response: {req.summary.get('avg_first_resp_hours', 0):.1f}h

MTTR
  Average: {req.mttr.get('avg_hours', 0):.1f}h | Median: {req.mttr.get('median_hours', 0):.1f}h
  P90: {req.mttr.get('p90_hours', 0):.1f}h | P95: {req.mttr.get('p95_hours', 0):.1f}h
  Total Closed: {req.mttr.get('total_closed', 0)}
  By Severity: {req.mttr.get('by_severity', [])}

SLA COMPLIANCE
{sla_lines}

OWNER WORKLOAD (top 10)
{owner_lines}

RECURRING INCIDENTS (top 8)
{recurrence_lines}

TREND
  Total incident volume in period: {total_trend}
"""

    system = (
        "You are a senior SOC manager and Microsoft Sentinel expert. "
        "Analyse the incident analytics data provided and produce a comprehensive, actionable assessment.\n\n"
        "Structure your response with these exact markdown sections:\n\n"
        "## Executive Summary\n"
        "2–3 sentence overall posture assessment. Lead with the most critical finding.\n\n"
        "## Key Findings\n"
        "Bulleted list of the 5–7 most significant observations from the data "
        "(volume, MTTR, SLA, workload imbalance, recurring patterns).\n\n"
        "## Risk Areas\n"
        "Identify the top 3 risk areas with supporting evidence from the stats. "
        "Rate each as Critical / High / Medium.\n\n"
        "## Operational Recommendations\n"
        "At least 5 concrete, actionable recommendations. For each:\n"
        "- **Action**: What to do\n"
        "- **Rationale**: Why — reference the specific metric that drives this\n"
        "- **Expected Outcome**: What improvement to expect\n\n"
        "## Recurring Incident Analysis\n"
        "Analyse the recurring incidents list. Are these false positives, detection rule issues, "
        "or genuine persistent threats? Recommend whether to tune, suppress, or escalate.\n\n"
        "## Priority Action Plan\n"
        "Numbered list of the top 5 actions in priority order. Include owner (SOC Lead / Detection Eng / "
        "Tier 1 / Management) and a suggested timeline (immediate / this week / this month).\n\n"
        "Be specific and data-driven. Reference actual numbers from the stats."
    )

    try:
        result = await llm_service.complete(system, context)
        return {
            "assessment":  result["text"],
            "token_usage": result["usage"],
        }
    except Exception as e:
        logger.error("LLM assessment failed: %s", e)
        raise HTTPException(status_code=500, detail=f"LLM assessment failed: {e}")


async def _enrich_entities(entities: list) -> str:
    """
    Enrich IP, domain/URL, and file-hash entities.
    Sources: AbuseIPDB + ipinfo + Shodan (via enrich_ips), VirusTotal v3, Sentinel TI.
    Returns a markdown section to inject into the LLM prompt, or "" if nothing enrichable.
    Any individual source failure is logged and silently skipped.
    """
    import re
    import os as _os
    import asyncio as _asyncio
    import sys
    from pathlib import Path
    import requests as _req

    if not entities:
        return ""

    _PRIVATE = re.compile(
        r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1$|localhost$)', re.I
    )

    ips:     list[str] = []
    domains: list[str] = []
    hashes:  list[str] = []

    for e in entities:
        etype = str(e.get("type", "")).lower()
        if etype == "ip":
            addr = (e.get("Address") or "").strip()
            if addr and not _PRIVATE.match(addr) and addr not in ips:
                ips.append(addr)
        elif etype in ("url", "uri"):
            url_val = (e.get("URL") or "").strip()
            m = re.search(r'https?://([^/?#\s]+)', url_val, re.I)
            if m:
                d = m.group(1).lower().rstrip(".")
                if d not in domains:
                    domains.append(d)
            elif url_val and url_val not in domains:
                domains.append(url_val)
        elif etype == "host":
            hostname = (e.get("FQDN") or e.get("Hostname") or "").strip()
            if hostname and "." in hostname and hostname not in domains:
                domains.append(hostname)
        elif etype == "dns":
            d = (e.get("Domain") or "").strip()
            if d and d not in domains:
                domains.append(d)
        elif etype == "file":
            h = (e.get("Hash") or "").strip()
            if h and len(h) >= 32 and h not in hashes:
                hashes.append(h)

    vt_key = _os.environ.get("VIRUSTOTAL_API_KEY", "")

    async def _vt(path: str) -> dict:
        """Single VirusTotal v3 GET, returns attributes dict or {} on any failure."""
        if not vt_key:
            return {}
        loop = _asyncio.get_event_loop()
        def _call():
            try:
                r = _req.get(
                    f"https://www.virustotal.com/api/v3/{path}",
                    headers={"x-apikey": vt_key}, timeout=10,
                )
                if r.status_code == 200:
                    return r.json().get("data", {}).get("attributes", {})
            except Exception:
                pass
            return {}
        return await loop.run_in_executor(None, _call)

    sections: list[str] = []

    # ── IP enrichment: AbuseIPDB/ipinfo/Shodan + VirusTotal ──────────────────
    if ips:
        loop = _asyncio.get_event_loop()
        enrich_future = None
        try:
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            import enrich_ips as _enrich_mod  # type: ignore
            enrich_future = loop.run_in_executor(
                None, lambda: _enrich_mod.enrich_ips(ips[:10], max_workers=5)
            )
        except Exception as _e:
            logger.warning("enrich_ips unavailable: %s", _e)

        vt_ip_coros = [_vt(f"ip_addresses/{ip}") for ip in ips[:10]]
        if enrich_future:
            all_ip = await _asyncio.gather(enrich_future, *vt_ip_coros, return_exceptions=True)
            enrich_list = all_ip[0] if not isinstance(all_ip[0], Exception) else []
            vt_ip_list  = list(all_ip[1:])
        else:
            vt_ip_list  = await _asyncio.gather(*vt_ip_coros, return_exceptions=True)
            enrich_list = []

        enrich_map = {r["ip"]: r for r in (enrich_list or []) if isinstance(r, dict) and "ip" in r}
        lines: list[str] = []
        for idx, ip in enumerate(ips[:10]):
            er  = enrich_map.get(ip, {})
            vt  = vt_ip_list[idx] if idx < len(vt_ip_list) and not isinstance(vt_ip_list[idx], Exception) else {}

            flags = []
            if er.get("is_vpn") or er.get("vpnapi_security_vpn"):    flags.append("VPN")
            if er.get("is_tor") or er.get("vpnapi_security_tor"):     flags.append("TOR")
            if er.get("is_proxy") or er.get("vpnapi_security_proxy"): flags.append("PROXY")
            if er.get("is_hosting"):                                   flags.append("HOSTING/DC")

            abuse_score = er.get("abuse_confidence_score", 0)
            reports     = er.get("total_reports", 0)
            country     = er.get("country") or vt.get("country", "?")
            org         = er.get("org") or vt.get("as_owner", "?")

            vt_stats   = vt.get("last_analysis_stats", {}) if isinstance(vt, dict) else {}
            vt_mal     = vt_stats.get("malicious", 0)
            vt_sus     = vt_stats.get("suspicious", 0)
            vt_total   = sum(vt_stats.values()) if vt_stats else 0
            vt_rep     = vt.get("reputation", "N/A") if isinstance(vt, dict) else "N/A"

            ports  = er.get("shodan_ports",  [])[:10]
            vulns  = er.get("shodan_vulns",  [])[:5]
            tags   = er.get("shodan_tags",   [])[:5]

            line = (
                f"- **{ip}** | {country} | {org}\n"
                f"  AbuseIPDB: {abuse_score}/100 ({reports} reports) | "
                f"VirusTotal: {vt_mal}/{vt_total} malicious, {vt_sus} suspicious (reputation: {vt_rep}) | "
                f"Flags: {', '.join(flags) if flags else 'None'}"
            )
            if ports:  line += f"\n  Open ports: {', '.join(str(p) for p in ports)}"
            if vulns:  line += f"\n  CVEs: {', '.join(vulns)}"
            if tags:   line += f"\n  Shodan tags: {', '.join(tags)}"
            lines.append(line)

        if lines:
            sections.append("### IP Intelligence (AbuseIPDB + VirusTotal + Shodan)\n" + "\n".join(lines))

    # ── Domain / URL enrichment: VirusTotal + Sentinel TI ────────────────────
    if domains:
        vt_dom_results = await _asyncio.gather(
            *[_vt(f"domains/{d}") for d in domains[:10]],
            return_exceptions=True,
        )
        lines = []
        for idx, domain in enumerate(domains[:10]):
            vt = vt_dom_results[idx] if idx < len(vt_dom_results) and not isinstance(vt_dom_results[idx], Exception) else {}
            vt_stats = vt.get("last_analysis_stats", {}) if isinstance(vt, dict) else {}
            vt_mal   = vt_stats.get("malicious", 0)
            vt_sus   = vt_stats.get("suspicious", 0)
            vt_total = sum(vt_stats.values()) if vt_stats else 0
            vt_rep   = vt.get("reputation", "N/A") if isinstance(vt, dict) else "N/A"
            cats     = ", ".join(list((vt.get("categories", {}) if isinstance(vt, dict) else {}).values())[:3])
            line = (
                f"- **{domain}** | VirusTotal: {vt_mal}/{vt_total} malicious, "
                f"{vt_sus} suspicious (reputation: {vt_rep})"
            )
            if cats:
                line += f" | Categories: {cats}"
            lines.append(line)

        # Sentinel TI supplement
        try:
            quoted = ", ".join(f'"{d}"' for d in domains[:15])
            ti_res = await run_kql(f"""
                ThreatIntelligenceIndicator
                | where TimeGenerated > ago(365d) and Active == true
                | where DomainName in ({quoted}) or Url has_any ({quoted})
                | project Indicator = coalesce(DomainName, Url),
                          ThreatType = IndicatorThreatType, Confidence, Severity = ThreatSeverity
                | limit 20
            """, days=365)
            for r in ti_res.get("rows", []):
                ind = r.get("Indicator", "")
                ti_str = f" | Sentinel TI: {r.get('ThreatType','?')} conf={r.get('Confidence','?')}"
                match_idx = next((j for j, l in enumerate(lines) if ind in l), None)
                if match_idx is not None:
                    lines[match_idx] += ti_str
                else:
                    lines.append(f"- **{ind}** |{ti_str}")
        except Exception as _e:
            logger.warning("Domain TI lookup skipped: %s", _e)

        if lines:
            sections.append("### Domain / URL Intelligence (VirusTotal + Sentinel TI)\n" + "\n".join(lines))

    # ── File hash enrichment: VirusTotal + Sentinel TI ────────────────────────
    if hashes:
        vt_hash_results = await _asyncio.gather(
            *[_vt(f"files/{h}") for h in hashes[:10]],
            return_exceptions=True,
        )
        lines = []
        for idx, h in enumerate(hashes[:10]):
            vt = vt_hash_results[idx] if idx < len(vt_hash_results) and not isinstance(vt_hash_results[idx], Exception) else {}
            vt_stats  = vt.get("last_analysis_stats", {}) if isinstance(vt, dict) else {}
            vt_mal    = vt_stats.get("malicious", 0)
            vt_sus    = vt_stats.get("suspicious", 0)
            vt_total  = sum(vt_stats.values()) if vt_stats else 0
            vt_rep    = vt.get("reputation", "N/A") if isinstance(vt, dict) else "N/A"
            name      = (vt.get("meaningful_name", "") if isinstance(vt, dict) else "")
            threat_lbl = ((vt.get("popular_threat_classification") or {}).get("suggested_threat_label", "") if isinstance(vt, dict) else "")
            line = (
                f"- **{h[:20]}…** | VirusTotal: {vt_mal}/{vt_total} malicious, "
                f"{vt_sus} suspicious (reputation: {vt_rep})"
            )
            if name:       line += f" | File: {name}"
            if threat_lbl: line += f" | Threat: **{threat_lbl}**"
            lines.append(line)

        # Sentinel TI supplement for hashes
        try:
            quoted = ", ".join(f'"{h}"' for h in hashes[:10])
            hash_ti = await run_kql(f"""
                ThreatIntelligenceIndicator
                | where TimeGenerated > ago(365d) and Active == true
                | where FileHashValue in ({quoted})
                | project Hash = FileHashValue, ThreatType = IndicatorThreatType,
                          Confidence, Description
                | limit 20
            """, days=365)
            for r in hash_ti.get("rows", []):
                hv = r.get("Hash", "")
                ti_str = f" | Sentinel TI: {r.get('ThreatType','?')} | {str(r.get('Description',''))[:80]}"
                match_idx = next((j for j, l in enumerate(lines) if hv[:20] in l), None)
                if match_idx is not None:
                    lines[match_idx] += ti_str
                else:
                    lines.append(f"- **{hv[:20]}…** |{ti_str}")
        except Exception as _e:
            logger.warning("Hash TI lookup skipped: %s", _e)

        if lines:
            sections.append("### File Hash Intelligence (VirusTotal + Sentinel TI)\n" + "\n".join(lines))

    if not sections:
        return ""
    return "\n\n## Entity Enrichment\n" + "\n\n".join(sections)


async def _enrich_entity_list(entities: list) -> list:
    """
    Enrich IP/domain/file-hash entities with AbuseIPDB + VirusTotal data for UI display.
    Returns a copy of the entity list with '_enrichment' dicts embedded where data is available.
    Private/loopback IPs are skipped. Any source failure is logged and skipped silently.
    """
    import re
    import os as _os
    import asyncio as _asyncio
    import sys
    from pathlib import Path
    import requests as _req

    if not entities:
        return entities

    vt_key = _os.environ.get("VIRUSTOTAL_API_KEY", "")
    _PRIVATE = re.compile(
        r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1$|localhost$)', re.I
    )

    ips:     list[str] = []
    domains: list[str] = []
    hashes:  list[str] = []

    for e in entities:
        etype = str(e.get("type", "")).lower()
        if etype == "ip":
            addr = (e.get("Address") or "").strip()
            if addr and not _PRIVATE.match(addr) and addr not in ips:
                ips.append(addr)
        elif etype in ("url", "uri"):
            url_val = (e.get("URL") or "").strip()
            m = re.search(r'https?://([^/?#\s]+)', url_val, re.I)
            d = m.group(1).lower().rstrip(".") if m else url_val
            if d and d not in domains:
                domains.append(d)
        elif etype == "host":
            hostname = (e.get("FQDN") or e.get("Hostname") or "").strip()
            if hostname and "." in hostname and hostname not in domains:
                domains.append(hostname)
        elif etype == "file":
            h = (e.get("Hash") or "").strip()
            if h and len(h) >= 32 and h not in hashes:
                hashes.append(h)

    if not ips and not domains and not hashes:
        return entities

    async def _vt(path: str) -> dict:
        if not vt_key:
            return {}
        loop = _asyncio.get_event_loop()
        def _call():
            try:
                r = _req.get(f"https://www.virustotal.com/api/v3/{path}",
                             headers={"x-apikey": vt_key}, timeout=10)
                if r.status_code == 200:
                    return r.json().get("data", {}).get("attributes", {})
            except Exception:
                pass
            return {}
        return await loop.run_in_executor(None, _call)

    loop = _asyncio.get_event_loop()
    enrich_future = None
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        import enrich_ips as _em  # type: ignore
        enrich_future = loop.run_in_executor(None, lambda: _em.enrich_ips(ips[:10], max_workers=5))
    except Exception as _e:
        logger.warning("enrich_ips unavailable: %s", _e)

    vt_coros = (
        [_vt(f"ip_addresses/{ip}") for ip in ips[:10]] +
        [_vt(f"domains/{d}")       for d  in domains[:10]] +
        [_vt(f"files/{h}")         for h  in hashes[:10]]
    )

    if enrich_future:
        all_res = await _asyncio.gather(enrich_future, *vt_coros, return_exceptions=True)
        enrich_list = all_res[0] if not isinstance(all_res[0], Exception) else []
        vt_flat = list(all_res[1:])
    else:
        vt_flat = list(await _asyncio.gather(*vt_coros, return_exceptions=True)) if vt_coros else []
        enrich_list = []

    n_ip  = len(ips[:10])
    n_dom = len(domains[:10])
    vt_ip_res   = vt_flat[:n_ip]
    vt_dom_res  = vt_flat[n_ip:n_ip + n_dom]
    vt_hash_res = vt_flat[n_ip + n_dom:]

    def _safe_vt(lst: list, idx: int) -> dict:
        v = lst[idx] if idx < len(lst) else {}
        return v if isinstance(v, dict) else {}

    enrich_map  = {r["ip"]:     r              for r in (enrich_list or []) if isinstance(r, dict) and "ip" in r}
    vt_ip_map   = {ips[i]:      _safe_vt(vt_ip_res,   i) for i in range(n_ip)}
    vt_dom_map  = {domains[i]:  _safe_vt(vt_dom_res,  i) for i in range(n_dom)}
    vt_hash_map = {hashes[i]:   _safe_vt(vt_hash_res, i) for i in range(len(hashes[:10]))}

    result = []
    for e in entities:
        entity = dict(e)
        etype  = str(e.get("type", "")).lower()

        if etype == "ip":
            addr = (e.get("Address") or "").strip()
            er   = enrich_map.get(addr, {})
            vt   = vt_ip_map.get(addr, {})
            vt_s = vt.get("last_analysis_stats", {}) if isinstance(vt, dict) else {}
            if er or vt_s:
                flags = []
                if er.get("is_vpn") or er.get("vpnapi_security_vpn"):    flags.append("VPN")
                if er.get("is_tor") or er.get("vpnapi_security_tor"):     flags.append("TOR")
                if er.get("is_proxy") or er.get("vpnapi_security_proxy"): flags.append("PROXY")
                if er.get("is_hosting"):                                   flags.append("HOSTING/DC")
                entity["_enrichment"] = {
                    "source":         "AbuseIPDB + VirusTotal",
                    "country":        er.get("country") or vt.get("country", ""),
                    "org":            er.get("org") or vt.get("as_owner", ""),
                    "abuse_score":    int(er.get("abuse_confidence_score", 0)),
                    "abuse_reports":  int(er.get("total_reports", 0)),
                    "flags":          flags,
                    "vt_malicious":   int(vt_s.get("malicious", 0)),
                    "vt_suspicious":  int(vt_s.get("suspicious", 0)),
                    "vt_total":       int(sum(vt_s.values())) if vt_s else 0,
                    "vt_reputation":  int(vt.get("reputation", 0)) if isinstance(vt, dict) else 0,
                    "shodan_ports":   er.get("shodan_ports", [])[:8],
                    "shodan_vulns":   er.get("shodan_vulns", [])[:5],
                }

        elif etype in ("url", "uri"):
            url_val = (e.get("URL") or "").strip()
            m = re.search(r'https?://([^/?#\s]+)', url_val, re.I)
            d = m.group(1).lower().rstrip(".") if m else url_val
            vt  = vt_dom_map.get(d, {})
            vt_s = vt.get("last_analysis_stats", {}) if isinstance(vt, dict) else {}
            if vt_s:
                cats = list((vt.get("categories") or {}).values())[:3]
                entity["_enrichment"] = {
                    "source":        "VirusTotal",
                    "vt_malicious":  int(vt_s.get("malicious", 0)),
                    "vt_suspicious": int(vt_s.get("suspicious", 0)),
                    "vt_total":      int(sum(vt_s.values())) if vt_s else 0,
                    "vt_reputation": int(vt.get("reputation", 0)) if isinstance(vt, dict) else 0,
                    "vt_categories": cats,
                }

        elif etype == "host":
            hostname = (e.get("FQDN") or e.get("Hostname") or "").strip()
            vt  = vt_dom_map.get(hostname, {})
            vt_s = vt.get("last_analysis_stats", {}) if isinstance(vt, dict) else {}
            if vt_s:
                entity["_enrichment"] = {
                    "source":        "VirusTotal",
                    "vt_malicious":  int(vt_s.get("malicious", 0)),
                    "vt_suspicious": int(vt_s.get("suspicious", 0)),
                    "vt_total":      int(sum(vt_s.values())) if vt_s else 0,
                    "vt_reputation": int(vt.get("reputation", 0)) if isinstance(vt, dict) else 0,
                }

        elif etype == "file":
            h   = (e.get("Hash") or "").strip()
            vt  = vt_hash_map.get(h, {})
            vt_s = vt.get("last_analysis_stats", {}) if isinstance(vt, dict) else {}
            if vt_s:
                threat_class = vt.get("popular_threat_classification") or {}
                entity["_enrichment"] = {
                    "source":             "VirusTotal",
                    "vt_malicious":       int(vt_s.get("malicious", 0)),
                    "vt_suspicious":      int(vt_s.get("suspicious", 0)),
                    "vt_total":           int(sum(vt_s.values())) if vt_s else 0,
                    "vt_reputation":      int(vt.get("reputation", 0)) if isinstance(vt, dict) else 0,
                    "vt_threat_label":    str(threat_class.get("suggested_threat_label", "")),
                    "vt_meaningful_name": str(vt.get("meaningful_name", "")),
                }

        result.append(entity)
    return result


def _kql_escape(s: str) -> str:
    """Escape a string for safe embedding inside a KQL double-quoted string literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


async def _collect_investigation_data(entities: list, incident_number: int, days: int = 7) -> list[dict]:
    """
    Run entity-specific KQL investigation queries and return structured results.
    Each entry: {label, query_type, rows, row_count}. Failed/empty queries are silently skipped.
    """
    import asyncio as _asyncio

    coros: list = []
    labels: list[str] = []
    qtypes: list[str] = []
    seen_accounts: set = set()
    seen_ips: set = set()
    seen_hosts: set = set()

    for e in entities[:8]:
        etype = str(e.get("type", "")).lower()

        if etype == "account":
            identifier = (e.get("UPN") or e.get("Name", "")).strip()
            if not identifier or identifier in seen_accounts:
                continue
            seen_accounts.add(identifier)
            esc = _kql_escape(identifier)

            coros.append(run_kql(f"""
SigninLogs
| where TimeGenerated > ago({days}d)
| where UserPrincipalName =~ "{esc}" or UserDisplayName =~ "{esc}"
| project TimeGenerated, User=UserPrincipalName, App=AppDisplayName, IP=IPAddress,
    Location=tostring(LocationDetails), ResultType,
    Risk=tostring(column_ifexists('RiskLevelDuringSignIn', '')),
    CA=tostring(column_ifexists('ConditionalAccessStatus', ''))
| order by TimeGenerated desc
| limit 20
""", days=days + 1))
            labels.append(f"Sign-in Logs: {identifier}")
            qtypes.append("signin")

            coros.append(run_kql(f"""
AuditLogs
| where TimeGenerated > ago({days}d)
| where tostring(InitiatedBy) contains "{esc}" or tostring(TargetResources) contains "{esc}"
| project TimeGenerated, OperationName, Result, Category,
    InitiatedBy=substring(tostring(InitiatedBy), 0, 200),
    Target=substring(tostring(TargetResources), 0, 200)
| order by TimeGenerated desc
| limit 15
""", days=days + 1))
            labels.append(f"Azure AD Audit: {identifier}")
            qtypes.append("audit")

        elif etype == "ip":
            addr = (e.get("Address", "") or "").strip()
            if not addr or addr in seen_ips:
                continue
            seen_ips.add(addr)
            esc = _kql_escape(addr)

            coros.append(run_kql(f"""
CommonSecurityLog
| where TimeGenerated > ago({days}d)
| where SourceIP =~ "{esc}" or DestinationIP =~ "{esc}"
| project TimeGenerated, DeviceVendor, Activity, SourceIP, DestinationIP, DestinationPort, Protocol, Message=substring(Message,0,300)
| order by TimeGenerated desc
| limit 20
""", days=days + 1))
            labels.append(f"Network Logs (CSL): {addr}")
            qtypes.append("network")

            coros.append(run_kql(f"""
SigninLogs
| where TimeGenerated > ago({days}d)
| where IPAddress =~ "{esc}"
| project TimeGenerated, User=UserPrincipalName, App=AppDisplayName, ResultType,
    Risk=tostring(column_ifexists('RiskLevelDuringSignIn', '')), Location=tostring(LocationDetails)
| order by TimeGenerated desc
| limit 15
""", days=days + 1))
            labels.append(f"Sign-ins from IP: {addr}")
            qtypes.append("signin")

        elif etype == "host":
            hostname = (e.get("Hostname") or e.get("FQDN") or "").strip()
            if not hostname or hostname in seen_hosts:
                continue
            seen_hosts.add(hostname)
            esc = _kql_escape(hostname)

            coros.append(run_kql(f"""
SecurityEvent
| where TimeGenerated > ago({days}d)
| where Computer contains "{esc}"
| where EventID in (4624, 4625, 4648, 4688, 4720, 4732, 4756, 7045)
| project TimeGenerated, Computer, EventID, Activity, Account,
    LogonType=tostring(column_ifexists('LogonType', '')),
    ProcessName=tostring(column_ifexists('NewProcessName', '')),
    CommandLine=substring(tostring(column_ifexists('CommandLine', '')), 0, 300),
    IpAddress=tostring(column_ifexists('IpAddress', ''))
| order by TimeGenerated desc
| limit 25
""", days=days + 1))
            labels.append(f"Security Events: {hostname}")
            qtypes.append("host")

            coros.append(run_kql(f"""
DeviceProcessEvents
| where TimeGenerated > ago({days}d)
| where DeviceName contains "{esc}"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine=substring(ProcessCommandLine,0,300),
    InitiatingProcessFileName, InitiatingProcessCommandLine=substring(InitiatingProcessCommandLine,0,200)
| order by TimeGenerated desc
| limit 20
""", days=days + 1))
            labels.append(f"Process Events: {hostname}")
            qtypes.append("process")

    # Related alerts for this incident (always run)
    coros.append(run_kql(f"""
SecurityAlert
| where TimeGenerated > ago({days + 90}d)
| where SystemAlertId in (
    SecurityIncident
    | where IncidentNumber == {incident_number}
    | mv-expand todynamic(AlertIds)
    | project tostring(AlertIds)
)
| project TimeGenerated, AlertName, Severity,
    Description=substring(Description, 0, 400),
    Tactics, Techniques,
    Entities=substring(tostring(Entities), 0, 400)
| order by TimeGenerated desc
| limit 10
""", days=days + 91))
    labels.append("Related Security Alerts")
    qtypes.append("alerts")

    results = await _asyncio.gather(*coros, return_exceptions=True)

    sections: list[dict] = []
    for label, qtype, result in zip(labels, qtypes, results):
        if isinstance(result, Exception):
            logger.debug("Investigation query [%s] skipped: %s", label, result)
            continue
        rows = result.get("rows", []) if isinstance(result, dict) else []
        if rows:
            sections.append({"label": label, "query_type": qtype, "rows": rows, "row_count": len(rows)})

    return sections


async def _run_investigation_queries(entities: list, incident_number: int, days: int = 7) -> str:
    """Format investigation data as a markdown section for LLM prompt context."""
    sections = await _collect_investigation_data(entities, incident_number, days)
    if not sections:
        return ""
    parts: list[str] = []
    for section in sections:
        lines = [f"### {section['label']} ({section['row_count']} records)"]
        for row in section["rows"]:
            cells = []
            for k, v in row.items():
                if v is None or v == "":
                    continue
                sv = str(v)
                if len(sv) > 250:
                    sv = sv[:250] + "…"
                cells.append(f"{k}: {sv}")
            lines.append("- " + " | ".join(cells))
        parts.append("\n".join(lines))
    return "\n\n## KQL Investigation Results\n\n" + "\n\n".join(parts)


@router.post("/analyze-incident")
async def analyze_single_incident(payload: dict):
    """Analyze a single incident with LLM and return targeted recommendations."""
    import asyncio as _asyncio

    inc = payload.get("incident", {})
    raw_entities: list = payload.get("entities", [])

    tactics = inc.get("tactics", "") or ""
    if isinstance(tactics, list):
        tactics = ", ".join(tactics)

    system = (
        "You are ARIA, an elite Tier-3 Cyber Security Analyst for the PwC Sentinel Engineering Team. "
        "Analyze the provided Microsoft Sentinel security incident and deliver:\n"
        "1. A concise severity and impact assessment\n"
        "2. Likely attack pattern and MITRE ATT&CK technique mapping\n"
        "3. Immediate recommended response actions (ranked by priority)\n"
        "4. Longer-term remediation and hardening steps\n"
        "5. Detection rule tuning suggestions if this may be recurring noise or a false positive\n"
        "6. If entity enrichment data is provided, explicitly reference it in your analysis — "
        "call out any malicious IPs (high abuse scores, VPN/Tor/proxy flags, CVEs), "
        "confirmed threat-intel matches for domains or file hashes, and how these affect the risk assessment.\n"
        "7. KQL investigation results are live workspace evidence — use them as primary source data: "
        "reference specific sign-in failures, process executions, network connections, and alert details "
        "to reconstruct the attack timeline and raise or lower your confidence in the threat assessment.\n\n"
        "Use markdown formatting with clear headings. Always include a summary table. "
        "Be direct, evidence-based, and actionable."
    )

    closed_str = inc.get("closed", "") or "Not yet closed"
    mttr = inc.get("mttr_hours", 0) or 0

    # Run enrichment and KQL investigation in parallel
    enrichment_section, investigation_section = await _asyncio.gather(
        _enrich_entities(raw_entities),
        _run_investigation_queries(raw_entities, inc.get("number", 0)),
        return_exceptions=False,
    )

    user_msg = (
        f"Analyze the following Microsoft Sentinel security incident:\n\n"
        f"## Incident Details\n"
        f"- **Incident #**: {inc.get('number', 'N/A')}\n"
        f"- **Title**: {inc.get('title', 'Unknown')}\n"
        f"- **Severity**: {inc.get('severity', 'Unknown')}\n"
        f"- **Status**: {inc.get('status', 'Unknown')}\n"
        f"- **Owner**: {inc.get('owner', 'Unassigned') or 'Unassigned'}\n"
        f"- **Created**: {inc.get('created', 'Unknown')}\n"
        f"- **Closed**: {closed_str}\n"
        f"- **MTTR**: {float(mttr):.1f}h\n"
        f"- **Tactics**: {tactics or 'Unknown'}\n"
        f"- **Classification**: {inc.get('classification', 'Unclassified') or 'Unclassified'}\n"
        f"- **Classification Comment**: {inc.get('classification_comment', '') or 'None'}\n\n"
        f"## Description\n"
        f"{inc.get('description', 'No description provided.') or 'No description provided.'}"
        f"{investigation_section}"
        f"{enrichment_section}\n\n"
        "Provide a thorough analysis with actionable recommendations."
    )

    try:
        result = await llm_service.complete(system, user_msg)
        return {"analysis": result["text"], "usage": result.get("usage", {})}
    except Exception as e:
        logger.error("Per-incident analysis failed: %s", e)
        raise HTTPException(status_code=500, detail=f"LLM analysis failed: {str(e)}")


@router.post("/incidents/{incident_number}/investigate")
async def investigate_incident(incident_number: int, payload: dict):
    """Run KQL investigation queries and return structured results for frontend display."""
    entities = payload.get("entities", [])
    days = max(1, min(int(payload.get("days", 7)), 90))
    try:
        sections = await _collect_investigation_data(entities, incident_number, days)
        return {
            "sections": sections,
            "total_records": sum(s["row_count"] for s in sections),
            "incident_number": incident_number,
            "days": days,
        }
    except Exception as e:
        logger.error("Investigation failed for #%s: %s", incident_number, e)
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.get("/incidents/{incident_number}/debug")
async def debug_incident_raw(incident_number: int):
    """
    Returns raw Sentinel data for an incident so entity/alert issues can be diagnosed.
    Shows the exact type and value that the Azure SDK returns for Entities and AlertIds.
    """
    import json as _json

    q = f"""
    SecurityIncident
    | where IncidentNumber == {incident_number}
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project
        IncidentNumber,
        Title,
        Status,
        IncidentName = tostring(column_ifexists("IncidentName", "")),
        Entities = column_ifexists("Entities", dynamic(null)),
        AlertIds  = column_ifexists("AlertIds",  dynamic(null))
    """
    try:
        res = await run_kql(q, days=365)
        rows = res.get("rows", [])
        if not rows:
            return {"found": False, "incident_number": incident_number}
        row = rows[0]
        ent_raw  = row.get("Entities")
        aid_raw  = row.get("AlertIds")
        return {
            "found": True,
            "title": row.get("Title", ""),
            "status": row.get("Status", ""),
            "incident_name": row.get("IncidentName", ""),
            "entities_python_type": type(ent_raw).__name__,
            "entities_value":       ent_raw,
            "entities_str_preview": str(ent_raw)[:600] if ent_raw is not None else None,
            "alert_ids_python_type": type(aid_raw).__name__,
            "alert_ids_value":       aid_raw,
            "alert_ids_str_preview": str(aid_raw)[:600] if aid_raw is not None else None,
        }
    except Exception as e:
        return {"error": str(e)}


def _parse_arm_entity(entity: dict) -> dict | None:
    """Parse one entity from the Sentinel ARM API /incidents/{id}/entities response."""
    kind = str(entity.get("kind", "")).strip()
    props = entity.get("properties") or {}
    if not isinstance(props, dict):
        props = {}

    kind_lower = kind.lower()
    fields: dict = {}

    if kind_lower == "account":
        fields["type"] = "Account"
        name = props.get("accountName", "")
        upn_suffix = props.get("upnSuffix", "")
        if name:
            fields["Name"] = name
        if name and upn_suffix:
            fields["UPN"] = f"{name}@{upn_suffix}"
        domain = props.get("ntDomain", "")
        if domain:
            fields["Domain"] = domain
        aad_id = props.get("aadUserId", "")
        if aad_id:
            fields["AAD ID"] = aad_id
        obj_guid = props.get("objectGuid", "")
        if obj_guid:
            fields["Object ID"] = obj_guid
    elif kind_lower == "ip":
        fields["type"] = "Ip"
        fields["Address"] = props.get("address", "")
    elif kind_lower == "host":
        fields["type"] = "Host"
        fields["Hostname"] = props.get("hostName") or props.get("netBiosName", "")
        fqdn = props.get("fqdn", "")
        if fqdn:
            fields["FQDN"] = fqdn
        osf = props.get("osFamily", "")
        if osf:
            fields["OS"] = osf
    elif kind_lower == "url":
        fields["type"] = "Url"
        fields["URL"] = props.get("url", "")
    elif kind_lower == "filehash":
        fields["type"] = "File"
        fields["Hash"] = props.get("hashValue", "")
        alg = props.get("algorithm", "")
        if alg:
            fields["Hash Type"] = alg
    elif kind_lower == "file":
        fields["type"] = "File"
        fn = props.get("fileName", "")
        if fn:
            fields["Name"] = fn
        d = props.get("directory", "")
        if d:
            fields["Path"] = d
    elif kind_lower == "dnsresolution":
        fields["type"] = "Dns"
        fields["Domain"] = props.get("domainName", "")
    elif kind_lower == "cloudapplication":
        fields["type"] = "Cloud"
        fields["App"] = props.get("appName", "")
        app_id = props.get("appId")
        if app_id:
            fields["App ID"] = str(app_id)
    elif kind_lower == "process":
        fields["type"] = "Process"
        pid = props.get("processId")
        if pid:
            fields["PID"] = str(pid)
        cmd = props.get("commandLine", "")
        if cmd:
            fields["Command"] = cmd
    elif kind_lower == "mailmessage":
        fields["type"] = "Mailmessage"
        subj = props.get("subject", "")
        if subj:
            fields["Subject"] = subj
        sender = props.get("p2Sender") or props.get("p1Sender") or ""
        if sender:
            fields["Sender"] = str(sender)
        recip = props.get("recipient", "")
        if recip:
            fields["Recipient"] = str(recip)
    elif kind_lower == "mailbox":
        fields["type"] = "Mailbox"
        addr = props.get("mailboxPrimaryAddress", "")
        if addr:
            fields["Address"] = addr
        dn = props.get("displayName", "")
        if dn:
            fields["Display"] = dn
    elif kind_lower == "registrykey":
        fields["type"] = "Registrykey"
        fields["Key"] = props.get("key", "")
    elif kind_lower == "registryvalue":
        fields["type"] = "Registryvalue"
        fields["Value Name"] = props.get("valueName", "")
        vd = props.get("valueData", "")
        if vd:
            fields["Value Data"] = vd
    elif kind_lower == "securitygroup":
        fields["type"] = "Group"
        dn = props.get("distinguishedName", "")
        if dn:
            fields["Name"] = dn
        sid = props.get("sid", "")
        if sid:
            fields["SID"] = sid
    elif kind_lower == "azureresource":
        fields["type"] = "AzureResource"
        fields["Resource ID"] = props.get("resourceId", "")
    elif kind_lower == "bookmark":
        fields["type"] = "Bookmark"
        fields["Name"] = props.get("displayName", "")
    elif kind_lower == "iotdevice":
        fields["type"] = "IoTDevice"
        fields["Name"] = props.get("deviceName", "")
        dt = props.get("deviceType", "")
        if dt:
            fields["Device Type"] = dt
    elif kind_lower == "securityalert":
        return None  # These are the alerts themselves, not indicators
    else:
        fields["type"] = kind or "Unknown"
        for k, v in props.items():
            if v and str(v).strip():
                fields[str(k)[:50]] = str(v)[:200]

    if not fields.get("type"):
        fields["type"] = kind or "Unknown"

    # Fallback: use friendlyName if no primary identifier was extracted
    friendly = props.get("friendlyName", "")
    if friendly and not any(fields.get(k) for k in
                            ["Name", "Address", "UPN", "URL", "Domain",
                             "Hash", "Hostname", "Resource ID"]):
        fields["Name"] = friendly

    clean = {k: v for k, v in fields.items() if v and str(v).strip()}
    return clean if len(clean) > 1 else None


async def _fetch_arm_entities(incident_name: str) -> list:
    """Fetch entities via POST /incidents/{id}/entities on the Sentinel ARM API."""
    from backend.services.sentinel import call_sentinel_mgmt_api_async
    try:
        result = await call_sentinel_mgmt_api_async(
            path=f"/incidents/{incident_name}/entities",
            api_version="2023-11-01",
            method="POST",
            body={},
        )
        raw_entities = result.get("entities") or []
        parsed = []
        for e in raw_entities:
            if not isinstance(e, dict):
                continue
            p = _parse_arm_entity(e)
            if p:
                parsed.append(p)
        logger.info("ARM API: %d raw → %d parsed entities for incident %s",
                    len(raw_entities), len(parsed), incident_name)
        return parsed
    except Exception as exc:
        logger.warning("ARM entity fetch failed for %s: %s", incident_name, exc)
        return []


async def _fetch_arm_incident_details(incident_name: str) -> dict:
    """Fetch full incident properties from GET /incidents/{id} for enriched tactics/classification."""
    from backend.services.sentinel import call_sentinel_mgmt_api_async
    try:
        result = await call_sentinel_mgmt_api_async(
            path=f"/incidents/{incident_name}",
            api_version="2023-11-01",
            method="GET",
        )
        props = result.get("properties") or {}
        additional = props.get("additionalData") or {}
        # tactics live in additionalData.tactics (inferred from alerts)
        tactics_list = additional.get("tactics") or props.get("tactics") or []
        tactics = ", ".join(str(t) for t in tactics_list if t) if isinstance(tactics_list, list) else str(tactics_list)
        return {
            "tactics":                props.get("classification") and tactics or tactics,
            "classification":         props.get("classification") or "",
            "classification_comment": props.get("classificationComment") or "",
        }
    except Exception as exc:
        logger.warning("ARM incident metadata fetch failed for %s: %s", incident_name, exc)
        return {}


async def _fetch_arm_alerts(incident_name: str) -> list:
    """Fetch alerts via POST /incidents/{id}/alerts on the Sentinel ARM API."""
    import json as _j
    from backend.services.sentinel import call_sentinel_mgmt_api_async
    try:
        result = await call_sentinel_mgmt_api_async(
            path=f"/incidents/{incident_name}/alerts",
            api_version="2023-11-01",
            method="POST",
            body={},
        )
        raw_alerts = result.get("value") or []
        parsed = []
        for a in raw_alerts:
            if not isinstance(a, dict):
                continue
            p = a.get("properties") or {}
            if not isinstance(p, dict):
                continue
            tactics_raw = p.get("tactics") or []
            tactics_str = ", ".join(str(t) for t in tactics_raw if t) if isinstance(tactics_raw, list) else str(tactics_raw)
            alert_ents = []
            for e in (p.get("entities") or []):
                if isinstance(e, dict):
                    pe = _parse_arm_entity(e)
                    if pe:
                        alert_ents.append(pe)
            extended = ""
            add_data = p.get("additionalData") or {}
            if add_data:
                try:
                    extended = _j.dumps(add_data)
                except Exception:
                    pass
            parsed.append({
                "time":        p.get("timeGenerated") or p.get("startTimeUtc", ""),
                "name":        p.get("alertDisplayName") or p.get("alertType", ""),
                "description": p.get("description", "") or "",
                "severity":    p.get("severity", ""),
                "provider":    p.get("vendorName") or p.get("productName", "") or "",
                "tactics":     tactics_str,
                "entities":    alert_ents,
                "extended":    extended,
            })
        logger.info("ARM alerts API: %d raw → %d parsed for incident %s",
                    len(raw_alerts), len(parsed), incident_name)
        return parsed
    except Exception as exc:
        logger.warning("ARM alerts fetch failed for %s: %s", incident_name, exc)
        return []


@router.get("/incidents/{incident_number}/details")
async def get_incident_details(incident_number: int):
    """Fetch entities and related security alerts for a specific incident."""
    import json as _json
    import asyncio as _asyncio

    # ── Entity parser ────────────────────────────────────────────────────────
    def _parse_one(item) -> dict | None:
        """Parse a single entity object (dict or JSON string) into a clean display dict."""
        if isinstance(item, str):
            try:
                item = _json.loads(item)
            except Exception:
                return None
        if not isinstance(item, dict):
            return None

        # Flatten nested Properties (some entity serialisations nest fields there)
        _props = item.get("Properties") or item.get("properties") or {}
        _lookup = {**item, **(dict(_props) if isinstance(_props, dict) else {})}
        # Build a lowercase key index for case-insensitive fallback
        _lower = {k.lower(): v for k, v in _lookup.items() if v}

        def _g(*keys: str) -> str:
            for k in keys:
                v = _lookup.get(k) or _lower.get(k.lower())
                if v:
                    return str(v)
            return ""

        raw_type = item.get("Type") or item.get("type") or ""
        if not raw_type:
            dotnet = item.get("$type", "")
            if "Account" in dotnet:              raw_type = "account"
            elif ".IP," in dotnet or "IpAddress" in dotnet: raw_type = "ip"
            elif "Host" in dotnet:               raw_type = "host"
            elif "Url" in dotnet:                raw_type = "url"
            elif "FileHash" in dotnet or ("File," in dotnet and "Profile" not in dotnet): raw_type = "file"
            elif "Process" in dotnet:            raw_type = "process"
            elif "MailMessage" in dotnet:        raw_type = "mailmessage"
            elif "Mailbox" in dotnet:            raw_type = "mailbox"
            elif "DnsResolution" in dotnet:      raw_type = "dns"
            elif "CloudApplication" in dotnet:   raw_type = "cloud"
            elif "RegistryKey" in dotnet:        raw_type = "registrykey"
            elif "RegistryValue" in dotnet:      raw_type = "registryvalue"
            elif "SecurityGroup" in dotnet:      raw_type = "group"
            elif "ServicePrincipal" in dotnet:   raw_type = "serviceprincipal"

        etype = str(raw_type).lower()
        fields: dict = {"type": etype.title() or "Unknown"}

        if etype == "account":
            fields["Name"]      = _g("Name")
            fields["UPN"]       = _g("UPNSuffix")
            fields["Domain"]    = _g("NTDomain")
            fields["AAD ID"]    = _g("AadUserId")
            fields["Object ID"] = _g("ObjectGuid")
        elif etype == "ip":
            fields["Address"]   = _g("Address")
        elif etype == "host":
            fields["Hostname"]  = _g("HostName", "NetBiosName")
            fields["FQDN"]      = _g("FQDN")
            fields["OS"]        = _g("OSFamily")
        elif etype in ("url", "uri"):
            fields["URL"]       = _g("Url")
        elif etype == "file":
            fields["Name"]      = _g("Name")
            fields["Path"]      = _g("Directory")
            fields["Hash"]      = _g("FileHashValue")
            fields["Hash Type"] = _g("FileHashType")
        elif etype == "dns":
            fields["Domain"]    = _g("DomainName")
        elif etype == "cloud":
            fields["App"]       = _g("Name")
            fields["App ID"]    = _g("AppId")
        elif etype == "process":
            fields["PID"]       = _g("ProcessId")
            fields["Command"]   = _g("CommandLine")
        elif etype == "mailbox":
            fields["Address"]   = _g("MailboxPrimaryAddress")
            fields["Display"]   = _g("DisplayName")
        elif etype == "mailmessage":
            fields["Subject"]   = _g("Subject")
            fields["Sender"]    = _g("Sender")
            fields["Recipient"] = _g("Recipient")
        elif etype in ("registrykey", "registryvalue"):
            fields["Key"]       = _g("Key")
            fields["Value"]     = _g("Value")
        elif etype in ("group", "serviceprincipal"):
            fields["Name"]      = _g("Name", "DisplayName")
            fields["Object ID"] = _g("ObjectGuid", "AadObjectId")
        else:
            for k, v in item.items():
                if not k.startswith("$") and k not in ("Type", "type") and v:
                    fields[str(k)] = str(v)[:200]

        clean = {k: v for k, v in fields.items() if v and str(v).strip()}
        return clean if len(clean) > 1 else None

    def _parse_entities_raw(raw) -> list:
        """
        Parse Sentinel entities from any SDK-serialized form:
        - list of dicts (modern SDK)
        - list of strings (some SDK versions serialize each element)
        - JSON string containing an array
        - single dict
        Handles $id/$ref internally and deduplicates.
        """
        if raw is None:
            return []
        if isinstance(raw, str):
            raw = raw.strip()
            if not raw or raw in ("[]", "null"):
                return []
            try:
                raw = _json.loads(raw)
            except Exception:
                return []
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list) or not raw:
            return []

        # Resolve $id/$ref: build map of id → full entity
        id_map: dict = {}
        for item in raw:
            if isinstance(item, dict) and "$id" in item and "$ref" not in item:
                id_map[str(item["$id"])] = item

        seen: set = set()
        out: list = []
        for item in raw:
            # Resolve references
            if isinstance(item, dict) and "$ref" in item and len(item) == 1:
                item = id_map.get(str(item["$ref"]), {})
                if not item:
                    continue
            parsed = _parse_one(item)
            if not parsed:
                continue
            etype = str(parsed.get("type", "")).lower()
            primary = (
                parsed.get("Address") or parsed.get("Name") or parsed.get("Hostname") or
                parsed.get("URL") or parsed.get("Hash") or parsed.get("Domain") or
                parsed.get("Subject") or parsed.get("App") or str(sorted(parsed.items()))
            )
            key = (etype, str(primary)[:120])
            if key not in seen:
                seen.add(key)
                out.append(parsed)
        return out

    def _dedup_key(e: dict) -> tuple:
        etype = str(e.get("type", "")).lower()
        primary = (
            e.get("Address") or e.get("Name") or e.get("Hostname") or
            e.get("URL") or e.get("Hash") or e.get("Domain") or
            e.get("Subject") or e.get("App") or str(sorted(e.items()))
        )
        return (etype, str(primary)[:120])

    # ── KQL 0: fetch IncidentName (ARM GUID) for the direct ARM API call
    incident_info_q = f"""
    SecurityIncident
    | where IncidentNumber == {incident_number}
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project IncidentName = tostring(column_ifexists("IncidentName", ""))
    | limit 1
    """

    # ── KQL 1: mv-expand Entities — one row per entity, each as a JSON string
    entities_q = f"""
    SecurityIncident
    | where IncidentNumber == {incident_number}
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where isnotempty(column_ifexists("Entities", dynamic(null)))
    | mv-expand Entity = column_ifexists("Entities", dynamic(null))
    | where isnotempty(Entity)
    | project EntityJson = tostring(Entity)
    """

    # ── KQL 2: alerts via AlertIds — normalise GUID from full ARM path on both sides
    alerts_q = f"""
    let incAlerts =
        SecurityIncident
        | where IncidentNumber == {incident_number}
        | summarize arg_max(TimeGenerated, *) by IncidentNumber
        | where isnotempty(column_ifexists("AlertIds", dynamic(null)))
        | mv-expand AlertIds
        | extend AlertIdRaw = tostring(AlertIds)
        | extend AlertId = iff(AlertIdRaw has "/",
                               tostring(split(AlertIdRaw, "/")[-1]),
                               AlertIdRaw);
    incAlerts
    | join kind=inner (
        SecurityAlert
        | extend NormId = iff(SystemAlertId has "/",
                              tostring(split(SystemAlertId, "/")[-1]),
                              SystemAlertId)
        | project
            NormId,
            AlertName,
            AlertDescription = tostring(column_ifexists("Description", "")),
            Severity,
            TimeGenerated,
            ProviderName       = tostring(column_ifexists("ProviderName", "")),
            Tactics            = tostring(column_ifexists("Tactics", "")),
            AlertEntities      = column_ifexists("Entities", dynamic(null)),
            ExtendedProperties = tostring(column_ifexists("ExtendedProperties", ""))
    ) on $left.AlertId == $right.NormId
    | project-away AlertId, NormId
    | order by TimeGenerated desc
    | limit 30
    """

    # ── KQL 3 (fallback): time-based SecurityAlert query when AlertIds join fails
    fallback_alerts_q = f"""
    let incTime = toscalar(
        SecurityIncident
        | where IncidentNumber == {incident_number}
        | summarize arg_max(TimeGenerated, *) by IncidentNumber
        | project coalesce(
            column_ifexists("CreatedTime", datetime(null)),
            TimeGenerated
        )
    );
    SecurityAlert
    | where isnotempty(incTime)
    | where TimeGenerated between (
        datetime_add('hour', -2, incTime) ..
        datetime_add('hour', 72, incTime)
      )
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | project
        AlertName,
        AlertDescription = tostring(column_ifexists("Description", "")),
        Severity,
        TimeGenerated,
        ProviderName       = tostring(column_ifexists("ProviderName", "")),
        Tactics            = tostring(column_ifexists("Tactics", "")),
        AlertEntities      = column_ifexists("Entities", dynamic(null)),
        ExtendedProperties = tostring(column_ifexists("ExtendedProperties", ""))
    | order by TimeGenerated desc
    | limit 20
    """

    def _process_alert_rows(rows: list) -> tuple[list, list]:
        """Return (alerts_list, new_entities_list) from SecurityAlert result rows."""
        new_alerts: list = []
        new_entities: list = []
        for r in rows:
            ae = _parse_entities_raw(r.get("AlertEntities"))
            new_alerts.append({
                "time":        r.get("TimeGenerated", ""),
                "name":        r.get("AlertName", ""),
                "description": r.get("AlertDescription", "") or "",
                "severity":    r.get("Severity", ""),
                "provider":    r.get("ProviderName", "") or "",
                "tactics":     r.get("Tactics", "") or "",
                "entities":    ae,
                "extended":    r.get("ExtendedProperties", "") or "",
            })
            new_entities.extend(ae)
        return new_alerts, new_entities

    try:
        info_res, ent_res, alert_res = await _asyncio.gather(
            run_kql(incident_info_q, days=365),
            run_kql(entities_q,      days=365),
            run_kql(alerts_q,        days=365),
            return_exceptions=True,
        )

        if isinstance(info_res,  Exception): logger.warning("IncidentName KQL failed: %s", info_res)
        if isinstance(ent_res,   Exception): logger.warning("Entities KQL failed: %s", ent_res)
        if isinstance(alert_res, Exception): logger.warning("Alerts KQL failed: %s", alert_res)

        entities:  list = []
        seen_keys: set  = set()

        # ── 1. ARM API — primary source (entities + incident metadata + alerts)
        incident_name = ""
        if isinstance(info_res, dict):
            info_rows = info_res.get("rows", [])
            if info_rows:
                incident_name = str(info_rows[0].get("IncidentName", "")).strip()

        incident_meta: dict = {}
        arm_alerts: list = []
        if incident_name:
            arm_ents_r, arm_meta_r, arm_alerts_r = await _asyncio.gather(
                _fetch_arm_entities(incident_name),
                _fetch_arm_incident_details(incident_name),
                _fetch_arm_alerts(incident_name),
                return_exceptions=True,
            )
            arm_ents   = arm_ents_r   if not isinstance(arm_ents_r,   Exception) else []
            incident_meta = arm_meta_r if not isinstance(arm_meta_r,   Exception) else {}
            arm_alerts = arm_alerts_r if not isinstance(arm_alerts_r, Exception) else []
            for ae in arm_ents:
                k = _dedup_key(ae)
                if k not in seen_keys:
                    seen_keys.add(k)
                    entities.append(ae)
            logger.info(
                "Incident %d: ARM — %d entities, meta=%s, %d alerts",
                incident_number, len(arm_ents), bool(incident_meta), len(arm_alerts),
            )

        # ── 2. Supplement with KQL entities from SecurityIncident.Entities
        if isinstance(ent_res, dict):
            for row in ent_res.get("rows", []):
                ejson = row.get("EntityJson", "")
                if not ejson:
                    continue
                try:
                    parsed = _parse_one(_json.loads(ejson))
                    if parsed:
                        k = _dedup_key(parsed)
                        if k not in seen_keys:
                            seen_keys.add(k)
                            entities.append(parsed)
                except Exception as _pe:
                    logger.debug("Entity parse error: %s | raw: %.100s", _pe, ejson)

        # ── 3. Alerts: ARM API first, KQL join as fallback
        alerts: list = []
        if arm_alerts:
            alerts = arm_alerts
            for a in arm_alerts:
                for ae in a.get("entities", []):
                    k = _dedup_key(ae)
                    if k not in seen_keys:
                        seen_keys.add(k)
                        entities.append(ae)
        elif isinstance(alert_res, dict) and alert_res.get("rows"):
            alerts, alert_entities = _process_alert_rows(alert_res["rows"])
            for ae in alert_entities:
                k = _dedup_key(ae)
                if k not in seen_keys:
                    seen_keys.add(k)
                    entities.append(ae)

        # ── 4. Fallback: time-based SecurityAlert query when join found nothing
        if not alerts:
            logger.info("Incident %d: AlertIds join returned nothing — running time-based fallback", incident_number)
            try:
                fb_res = await run_kql(fallback_alerts_q, days=365)
                if isinstance(fb_res, dict) and fb_res.get("rows"):
                    alerts, fallback_entities = _process_alert_rows(fb_res["rows"])
                    for ae in fallback_entities:
                        k = _dedup_key(ae)
                        if k not in seen_keys:
                            seen_keys.add(k)
                            entities.append(ae)
                    logger.info("Fallback found %d alerts for incident %d", len(alerts), incident_number)
            except Exception as _fb_e:
                logger.warning("Fallback alert query failed: %s", _fb_e)

        logger.info(
            "Incident %d: %d entities, %d alerts before enrichment (incident_name=%r)",
            incident_number, len(entities), len(alerts), incident_name,
        )

        # ── 5. Enrich IP/URL/hash entities with VT + AbuseIPDB for UI display
        try:
            entities = await _enrich_entity_list(entities)
        except Exception as _ee:
            logger.warning("Entity enrichment failed (returning unenriched): %s", _ee)

        return {"entities": entities, "alerts": alerts, "incident_metadata": incident_meta}

    except Exception as e:
        logger.error("Incident details fetch failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to fetch incident details: {str(e)}")


# ─────────────────────────────────────────────────────────────────────────────
# Priority Ranking, Email Reports, Enrichment Comments
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/priority-ranking")
async def rank_incidents_by_priority(payload: dict):
    """LLM-assigns priority 1–5 to each incident and returns sorted list."""
    incidents = payload.get("incidents", [])[:60]
    if not incidents:
        return {"ranked": []}

    lines = [
        f"#{inc.get('number','?')} | Sev:{inc.get('severity','?')} | "
        f"Status:{inc.get('status','?')} | MTTR:{float(inc.get('mttr_hours') or 0):.0f}h | "
        f"Tactics:{inc.get('tactics') or 'None'} | Title:{inc.get('title','?')}"
        for inc in incidents
    ]

    system = (
        "You are ARIA, an elite Tier-3 Cyber Security Analyst.\n"
        "Analyze these Microsoft Sentinel incidents and assign each a priority score 1–5:\n"
        "  5 = Critical: Active attack, credential theft, lateral movement, data exfiltration\n"
        "  4 = High: Privilege escalation, persistence, suspicious auth, C2 indicators\n"
        "  3 = Medium: Anomalous behavior, policy violations, moderate-confidence detections\n"
        "  2 = Low: Low-confidence alerts, borderline informational, likely false positive\n"
        "  1 = Minimal: Noise, benign patterns, already closed with no escalation needed\n\n"
        "Respond ONLY with a valid JSON array — no other text:\n"
        '[{"number": 123, "priority": 5, "reason": "One concise sentence."}]'
    )
    user_msg = "Assign priority to these Sentinel incidents:\n\n" + "\n".join(lines)

    try:
        result = await llm_service.complete(system, user_msg)
        text = result["text"].strip()
        m = _re_g.search(r'\[.*\]', text, _re_g.DOTALL)
        ranked_raw = _json_g.loads(m.group(0)) if m else _json_g.loads(text)
        priority_map = {
            int(r["number"]): r
            for r in ranked_raw
            if isinstance(r, dict) and "number" in r
        }
        result_list = []
        for inc in incidents:
            try:
                num = int(inc.get("number") or 0)
            except (TypeError, ValueError):
                num = 0
            p = priority_map.get(num, {})
            result_list.append({
                **inc,
                "priority_score": int(p.get("priority", 3)),
                "priority_reason": str(p.get("reason", "")),
            })
        result_list.sort(key=lambda x: (-x["priority_score"], -(float(x.get("mttr_hours") or 0))))
        return {"ranked": result_list}
    except Exception as e:
        logger.error("Priority ranking failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Priority ranking failed: {e}")


def _priority_label(score: int) -> tuple[str, str]:
    """(display_label, hex_color) for priority 1–5."""
    return {
        5: ("P5 — Critical", "#C0392B"),
        4: ("P4 — High",     "#E67E22"),
        3: ("P3 — Medium",   "#F39C12"),
        2: ("P2 — Low",      "#27AE60"),
        1: ("P1 — Minimal",  "#7F8C8D"),
    }.get(score, ("P3 — Medium", "#F39C12"))


def _sev_color_email(sev: str) -> str:
    return {"High": "#C0392B", "Medium": "#E67E22", "Low": "#27AE60"}.get(sev, "#3498DB")


def _build_incident_email_html(
    incidents: list,
    summary: dict,
    days: int,
    app_url: str,
    generated_at: str,
    briefs: dict,
) -> str:
    """Assemble the full decorated HTML email body for an incident priority report."""
    from collections import defaultdict as _dd

    brand   = "#D04A02"
    dark_bg = "#1A1E2E"
    card_bg = "#FFFFFF"
    border  = "#E5E7EB"
    t_pri   = "#1F2937"
    t_mut   = "#6B7280"

    def sev_badge(sev: str) -> str:
        c = _sev_color_email(sev)
        return (f'<span style="background:{c}22;color:{c};font-size:11px;font-weight:700;'
                f'padding:2px 10px;border-radius:20px">{sev}</span>')

    def status_badge(status: str) -> str:
        c = "#27AE60" if status == "Closed" else "#C0392B"
        return (f'<span style="background:{c}22;color:{c};font-size:11px;font-weight:700;'
                f'padding:2px 10px;border-radius:20px">{status}</span>')

    def btn(text: str, url: str, bg: str, fg: str = "#FFFFFF") -> str:
        return (f'<a href="{url}" style="display:inline-block;padding:7px 16px;background:{bg};'
                f'color:{fg};text-decoration:none;border-radius:6px;font-size:12px;font-weight:700;'
                f'margin-right:8px;margin-bottom:6px;white-space:nowrap">{text}</a>')

    groups: dict = _dd(list)
    for inc in incidents:
        groups[inc.get("priority_score", 3)].append(inc)

    sections_html = ""
    for score in sorted(groups.keys(), reverse=True):
        plabel, pcolor = _priority_label(score)
        cards = ""
        for inc in groups[score]:
            num     = inc.get("number", "?")
            title   = inc.get("title", "Unknown")
            sev     = inc.get("severity", "Unknown")
            status  = inc.get("status", "Unknown")
            owner   = inc.get("owner", "Unassigned")
            created = str(inc.get("created") or "")[:16].replace("T", " ")
            tactics = inc.get("tactics") or ""
            mttr    = float(inc.get("mttr_hours") or 0)
            reason  = inc.get("priority_reason", "")
            try:
                brief_key = int(num)
            except (TypeError, ValueError):
                brief_key = str(num)
            brief_text = briefs.get(brief_key) or briefs.get(str(num), "")

            mttr_c  = "#C0392B" if mttr > 24 else "#E67E22" if mttr > 8 else "#27AE60"
            mttr_s  = f"{mttr:.1f}h" if mttr < 48 else f"{mttr/24:.1f}d"

            tactic_tags = "".join(
                f'<span style="background:#FEF3C7;color:#92400E;font-size:10px;font-weight:700;'
                f'padding:2px 8px;border-radius:12px;margin-right:4px">{t.strip()}</span>'
                for t in tactics.split(",") if t.strip()
            )

            # Enrichment table (only for top-ranked incidents that have _enrichment_summary)
            enr_rows = ""
            for e in inc.get("_enrichment_summary", [])[:6]:
                mal   = e.get("vt_malicious", 0)
                vtot  = e.get("vt_total", 0)
                abuse = e.get("abuse_score", 0)
                vc    = "#C0392B" if mal > 0 else "#27AE60"
                ac    = "#C0392B" if abuse > 50 else "#E67E22" if abuse > 20 else "#27AE60"
                enr_rows += (
                    f'<tr><td style="padding:5px 10px;border-bottom:1px solid {border};font-size:11px;font-family:monospace">{e.get("value","")}</td>'
                    f'<td style="padding:5px 10px;border-bottom:1px solid {border};font-size:11px">{e.get("type","").upper()}</td>'
                    f'<td style="padding:5px 10px;border-bottom:1px solid {border};font-size:11px;color:{vc};font-weight:600">{mal}/{vtot} malicious</td>'
                    f'<td style="padding:5px 10px;border-bottom:1px solid {border};font-size:11px;color:{ac};font-weight:600">{abuse}/100</td></tr>'
                )
            enr_section = ""
            if enr_rows:
                enr_section = (
                    f'<div style="margin-top:12px">'
                    f'<div style="font-size:10px;font-weight:700;color:{t_mut};text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px">Threat Intelligence (VT + AbuseIPDB)</div>'
                    f'<table style="border-collapse:collapse;width:100%;border:1px solid {border};border-radius:6px">'
                    f'<thead><tr style="background:#F9FAFB">'
                    f'<th style="padding:6px 10px;text-align:left;font-size:10px;color:{t_mut};font-weight:700;text-transform:uppercase">Indicator</th>'
                    f'<th style="padding:6px 10px;text-align:left;font-size:10px;color:{t_mut};font-weight:700;text-transform:uppercase">Type</th>'
                    f'<th style="padding:6px 10px;text-align:left;font-size:10px;color:{t_mut};font-weight:700;text-transform:uppercase">VirusTotal</th>'
                    f'<th style="padding:6px 10px;text-align:left;font-size:10px;color:{t_mut};font-weight:700;text-transform:uppercase">AbuseIPDB</th>'
                    f'</tr></thead><tbody>{enr_rows}</tbody></table></div>'
                )

            view_url    = f"{app_url}?page=incidents" if app_url else "#"
            comment_url = f"{app_url}/api/incident-analytics/incidents/{num}/comment-form"
            enrich_url  = f"{app_url}/api/incident-analytics/incidents/{num}/enrich-comment-confirm"

            cards += f"""
<div style="background:{card_bg};border:1px solid {border};border-left:4px solid {pcolor};border-radius:8px;margin-bottom:14px">
  <div style="padding:14px 18px;background:#FAFAFA;border-bottom:1px solid {border}">
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
      <span style="font-size:12px;color:{t_mut}">#{num}</span>
      {sev_badge(sev)} {status_badge(status)}
      <span style="margin-left:auto;font-size:11px;font-weight:700;color:{mttr_c}">MTTR: {mttr_s}</span>
    </div>
    <div style="font-size:14px;font-weight:700;color:{t_pri};line-height:1.4">{title}</div>
    {f'<div style="margin-top:6px;font-size:12px;color:{t_mut};padding:4px 10px;background:#F3F4F6;border-radius:6px;font-style:italic">{reason}</div>' if reason else ''}
  </div>
  <div style="padding:14px 18px">
    <div style="display:flex;flex-wrap:wrap;gap:18px;margin-bottom:12px">
      <div><span style="font-size:10px;font-weight:700;color:{t_mut};text-transform:uppercase;display:block;margin-bottom:2px">Owner</span><span style="font-size:12px;color:{t_pri};font-weight:600">{owner}</span></div>
      <div><span style="font-size:10px;font-weight:700;color:{t_mut};text-transform:uppercase;display:block;margin-bottom:2px">Created</span><span style="font-size:12px;color:{t_pri}">{created}</span></div>
      {f'<div><span style="font-size:10px;font-weight:700;color:{t_mut};text-transform:uppercase;display:block;margin-bottom:4px">Tactics</span>{tactic_tags}</div>' if tactic_tags else ''}
    </div>
    {f'<div style="background:rgba(208,74,2,0.05);border:1px solid rgba(208,74,2,0.15);border-left:3px solid {brand};border-radius:6px;padding:12px;margin-bottom:12px"><div style="font-size:10px;font-weight:700;color:{brand};text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px">AI Analysis Brief</div><div style="font-size:12px;color:{t_pri};line-height:1.7">{brief_text}</div></div>' if brief_text else ''}
    {enr_section}
    <div style="margin-top:14px;padding-top:12px;border-top:1px solid {border}">
      {btn("View in Sentinel Vigil", view_url, brand)}
      {btn("Add Comment", comment_url, "#374151")}
      {btn("Add Enrichment Analysis as Comment", enrich_url, "#1E40AF")}
    </div>
  </div>
</div>"""

        p4_count = len(groups[score])
        sections_html += f"""
<div style="margin-bottom:28px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;padding-bottom:10px;border-bottom:2px solid {pcolor}">
    <span style="background:{pcolor};color:#fff;font-size:11px;font-weight:800;padding:4px 14px;border-radius:20px">{plabel}</span>
    <span style="font-size:12px;color:{t_mut}">{p4_count} incident{'s' if p4_count != 1 else ''}</span>
  </div>
  {cards}
</div>"""

    total     = summary.get("total", len(incidents))
    open_c    = summary.get("open", sum(1 for i in incidents if i.get("status") not in ("Closed",)))
    high_c    = summary.get("high_count", sum(1 for i in incidents if i.get("severity") == "High"))
    p4plus    = sum(1 for i in incidents if i.get("priority_score", 0) >= 4)
    st_style  = f"background:{card_bg};border:1px solid {border};border-radius:8px;padding:16px 20px;text-align:center;flex:1;min-width:80px"
    key_items = "".join(
        f'<span style="background:{c}22;color:{c};font-size:11px;font-weight:700;padding:3px 12px;border-radius:20px;margin-right:6px">{l}</span>'
        for l, c in [("P5 Critical","#C0392B"),("P4 High","#E67E22"),("P3 Medium","#F39C12"),("P2 Low","#27AE60"),("P1 Minimal","#7F8C8D")]
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Vigil — Incident Priority Report</title></head>
<body style="margin:0;padding:0;background:#F3F4F6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<div style="max-width:820px;margin:0 auto;padding:24px 16px">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,{dark_bg} 0%,#2D3250 100%);border-radius:12px;padding:32px;margin-bottom:20px;text-align:center">
    <div style="font-size:24px;font-weight:800;color:#FFFFFF;margin-bottom:6px">🛡 Sentinel Vigil</div>
    <div style="font-size:16px;font-weight:600;color:{brand};margin-bottom:10px">Incident Priority Report</div>
    <div style="font-size:13px;color:#9CA3AF">Period: Last {days} days &nbsp;·&nbsp; Generated: {generated_at} &nbsp;·&nbsp; {len(incidents)} active incidents analysed</div>
  </div>

  <!-- Summary -->
  <div style="margin-bottom:20px">
    <div style="font-size:12px;font-weight:700;color:{t_mut};text-transform:uppercase;letter-spacing:0.06em;margin-bottom:10px">Summary</div>
    <div style="display:flex;gap:12px;flex-wrap:wrap">
      <div style="{st_style}"><div style="font-size:28px;font-weight:800;color:{brand}">{total}</div><div style="font-size:11px;color:{t_mut};font-weight:700;text-transform:uppercase;margin-top:4px">Total Active</div></div>
      <div style="{st_style}"><div style="font-size:28px;font-weight:800;color:#C0392B">{open_c}</div><div style="font-size:11px;color:{t_mut};font-weight:700;text-transform:uppercase;margin-top:4px">Open</div></div>
      <div style="{st_style}"><div style="font-size:28px;font-weight:800;color:#E67E22">{high_c}</div><div style="font-size:11px;color:{t_mut};font-weight:700;text-transform:uppercase;margin-top:4px">High Severity</div></div>
      <div style="{st_style}"><div style="font-size:28px;font-weight:800;color:#1E40AF">{p4plus}</div><div style="font-size:11px;color:{t_mut};font-weight:700;text-transform:uppercase;margin-top:4px">P4 / P5 Priority</div></div>
    </div>
  </div>

  <!-- Priority key -->
  <div style="background:{card_bg};border:1px solid {border};border-radius:8px;padding:14px 18px;margin-bottom:24px">
    <div style="font-size:11px;font-weight:700;color:{t_mut};text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px">Priority Key</div>
    <div>{key_items}</div>
  </div>

  <!-- Incident groups -->
  {sections_html if sections_html else f'<div style="text-align:center;padding:40px;color:{t_mut}">No incidents to display</div>'}

  <!-- Footer -->
  <div style="text-align:center;padding:24px 0;border-top:1px solid {border};margin-top:8px">
    <div style="font-size:12px;color:{t_mut}">Generated by <strong style="color:{brand}">Sentinel Vigil</strong> · Microsoft Sentinel Security Operations Platform</div>
    <div style="font-size:11px;color:{t_mut};margin-top:4px">{generated_at}</div>
  </div>
</div></body></html>"""


async def _send_graph_mail(to_list: list[str], subject: str, html_body: str) -> None:
    """Send an HTML email via Microsoft Graph API (client-credentials flow)."""
    import urllib.request
    import urllib.parse
    import urllib.error
    from backend.config import settings

    from_addr = settings.GRAPH_MAIL_FROM
    tenant_id = settings.TENANT_ID
    client_id = settings.GRAPH_CLIENT_ID
    client_secret = settings.GRAPH_CLIENT_SECRET

    if not from_addr:
        raise ValueError("GRAPH_MAIL_FROM is not configured — set it in .env or Settings page")
    if not tenant_id or not client_id or not client_secret:
        raise ValueError(
            "Graph mail requires AZURE_TENANT_ID, AZURE_CLIENT_ID (or GRAPH_CLIENT_ID), "
            "and AZURE_CLIENT_SECRET (or GRAPH_CLIENT_SECRET)"
        )
    if not to_list:
        raise ValueError("No recipients specified")

    import asyncio as _aio

    def _do_send():
        import json as _j
        # 1. Acquire token
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        token_data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }).encode()
        token_req = urllib.request.Request(token_url, data=token_data, method="POST")
        with urllib.request.urlopen(token_req, timeout=30) as r:
            token_resp = _j.loads(r.read())
        access_token = token_resp.get("access_token")
        if not access_token:
            raise RuntimeError(f"Failed to obtain Graph token: {token_resp.get('error_description', token_resp)}")

        # 2. Build sendMail payload
        payload = _j.dumps({
            "message": {
                "subject": subject,
                "body": {"contentType": "HTML", "content": html_body},
                "toRecipients": [{"emailAddress": {"address": addr}} for addr in to_list],
                "from": {"emailAddress": {"address": from_addr}},
            },
            "saveToSentItems": "true",
        }).encode("utf-8")

        mail_url = f"https://graph.microsoft.com/v1.0/users/{urllib.parse.quote(from_addr)}/sendMail"
        mail_req = urllib.request.Request(
            mail_url, data=payload, method="POST",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(mail_req, timeout=30) as r:
            # 202 Accepted — no body
            pass

    loop = _aio.get_event_loop()
    await loop.run_in_executor(None, _do_send)


@router.post("/send-email-report")
async def send_email_report(req: EmailReportRequest):
    """
    Fetch active incidents for the period, rank by LLM priority, optionally enrich top
    incidents via VT + AbuseIPDB, generate AI briefs, then send a decorated HTML email.
    """
    import asyncio as _aio
    import os as _os
    import requests as _rq
    from datetime import datetime as _dt

    if not req.to:
        raise HTTPException(status_code=400, detail="At least one recipient email is required")

    # 1. Fetch active incidents
    days = req.days
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status in ("Active", "New")
    | extend OwnerName = iff(
        isempty(Owner) or Owner == "null" or Owner == "{{}}",
        "Unassigned",
        coalesce(
            tostring(todynamic(Owner).userPrincipalName),
            tostring(todynamic(Owner).assignedTo),
            "Unassigned"
        )
      )
    | extend OwnerName = iff(OwnerName == "null" or OwnerName == "", "Unassigned", OwnerName)
    | extend MTTR_Hours = toreal(datetime_diff('hour', now(), CreatedTime))
    | project
        IncidentNumber, Title, Severity, Status, OwnerName, CreatedTime, MTTR_Hours,
        Tactics     = column_ifexists("Tactics",      dynamic(null)),
        Description = tostring(column_ifexists("Description", ""))
    | sort by CreatedTime desc
    | limit {req.max_incidents}
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch incidents: {e}")

    def _tactics(raw) -> str:
        if raw is None or raw == "":
            return ""
        if isinstance(raw, list):
            return ", ".join(str(t) for t in raw if t)
        s = str(raw).strip()
        if s.startswith("["):
            try:
                arr = _json_g.loads(s)
                if isinstance(arr, list):
                    return ", ".join(str(t) for t in arr if t)
            except Exception:
                pass
        return s

    incidents = [{
        "number":      r.get("IncidentNumber", ""),
        "title":       r.get("Title", ""),
        "severity":    r.get("Severity", "Unknown"),
        "status":      r.get("Status", "Unknown"),
        "owner":       r.get("OwnerName", "Unassigned"),
        "created":     r.get("CreatedTime", ""),
        "mttr_hours":  float(r.get("MTTR_Hours") or 0),
        "tactics":     _tactics(r.get("Tactics")),
        "description": r.get("Description", "") or "",
        "closed": "", "last_updated": "",
        "classification": "", "classification_comment": "",
    } for r in rows]

    if not incidents:
        raise HTTPException(
            status_code=404,
            detail=f"No active incidents found in the last {days} days"
        )

    # Filter to caller-selected incidents if specified
    if req.incident_numbers:
        selected = set(req.incident_numbers)
        incidents = [i for i in incidents if i["number"] in selected]
        if not incidents:
            raise HTTPException(
                status_code=404,
                detail="None of the selected incident numbers were found as active incidents"
            )

    # 2. Priority ranking via LLM
    try:
        ranked = (await rank_incidents_by_priority({"incidents": incidents}))["ranked"]
    except Exception as e:
        logger.warning("Priority ranking unavailable, using severity fallback: %s", e)
        ranked = incidents
        _fallback = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1}
        for inc in ranked:
            inc["priority_score"]  = _fallback.get(inc.get("severity", ""), 3)
            inc["priority_reason"] = ""

    # 3. Batch LLM briefs — single call for all incidents (optional)
    briefs: dict = {}
    llm_brief_error: str = ""
    if req.include_llm:
        try:
            brief_lines = []
            for inc in ranked:
                desc = (inc.get("description") or "")[:200].replace("\n", " ")
                desc_part = f" | Desc:{desc}" if desc else ""
                brief_lines.append(
                    f"{inc['number']}: [{inc['severity']}] {inc['title']}"
                    f" | Tactics:{inc.get('tactics','None') or 'None'}{desc_part}"
                )
            brief_system = (
                "You are ARIA, a Tier-3 Cyber Security Analyst. "
                "For each incident write exactly 2 sentences: "
                "first sentence identifies the most likely threat or attack pattern, "
                "second sentence states the single most critical immediate action. "
                "Be specific to the incident title and description. "
                "Respond ONLY as a valid JSON object — no markdown, no other text:\n"
                '{"123": "Threat sentence. Action sentence.", "456": "..."}'
            )
            brief_user = "Write 2-sentence investigation briefs:\n\n" + "\n".join(brief_lines)
            br = await llm_service.complete(brief_system, brief_user)
            btext = br["text"].strip()
            # Strip markdown code fences if present
            btext = _re_g.sub(r'^```[a-z]*\n?', '', btext, flags=_re_g.MULTILINE)
            btext = btext.replace('```', '')
            bm = _re_g.search(r'\{.*\}', btext, _re_g.DOTALL)
            if bm:
                raw_b = _json_g.loads(bm.group(0))
                for k, v in raw_b.items():
                    k_clean = str(k).lstrip('#').strip()
                    try:
                        briefs[int(k_clean)] = str(v)
                    except (ValueError, TypeError):
                        briefs[k_clean] = str(v)
            logger.info("LLM briefs generated for %d incidents", len(briefs))
        except Exception as e:
            llm_brief_error = str(e)
            logger.warning("Batch briefs LLM call failed: %s", e)

    # Fallback: use description snippet when LLM brief is missing
    for inc in ranked:
        num = inc.get("number")
        try:
            key = int(num)
        except (TypeError, ValueError):
            key = str(num)
        if not briefs.get(key) and not briefs.get(str(num), ""):
            desc = (inc.get("description") or "").strip()
            title = inc.get("title", "")
            tactics = inc.get("tactics") or ""
            if desc:
                fallback = desc[:300] + ("…" if len(desc) > 300 else "")
            else:
                tact_part = f" Tactics: {tactics}." if tactics else ""
                fallback = f"{title}.{tact_part} No further description available."
            briefs[key] = fallback

    # 4. Enrich top P4/P5 incidents (optional)
    if req.include_enrichment:
        vt_key = _os.environ.get("VIRUSTOTAL_API_KEY", "")
        ab_key = _os.environ.get("ABUSEIPDB_TOKEN", "")
        top    = [i for i in ranked if i.get("priority_score", 0) >= 4][:8]

        for inc in top:
            num = inc.get("number")
            try:
                info_q = (
                    f"SecurityIncident | where IncidentNumber == {num}"
                    " | summarize arg_max(TimeGenerated, *) by IncidentNumber"
                    " | project IncidentName = tostring(column_ifexists('IncidentName', '')) | limit 1"
                )
                info_rows = (await run_kql(info_q, days=365)).get("rows", [])
                if not info_rows:
                    continue
                inc_name = str(info_rows[0].get("IncidentName", "")).strip()
                if not inc_name:
                    continue
                entities = await _fetch_arm_entities(inc_name)
                enr_list = []
                for ent in entities[:8]:
                    etype = str(ent.get("type", "")).lower()
                    entry: dict = {"type": etype}
                    if etype == "ip":
                        addr = ent.get("Address", "")
                        if not addr:
                            continue
                        entry["value"] = addr
                        if ab_key:
                            try:
                                r = _rq.get(
                                    "https://api.abuseipdb.com/api/v2/check",
                                    params={"ipAddress": addr, "maxAgeInDays": 90},
                                    headers={"Key": ab_key, "Accept": "application/json"},
                                    timeout=8,
                                )
                                if r.status_code == 200:
                                    d = r.json().get("data", {})
                                    entry["abuse_score"] = d.get("abuseConfidenceScore", 0)
                            except Exception:
                                pass
                        if vt_key:
                            try:
                                r = _rq.get(
                                    f"https://www.virustotal.com/api/v3/ip_addresses/{addr}",
                                    headers={"x-apikey": vt_key}, timeout=8,
                                )
                                if r.status_code == 200:
                                    attrs = r.json().get("data", {}).get("attributes", {})
                                    stats = attrs.get("last_analysis_stats", {})
                                    entry["vt_malicious"] = stats.get("malicious", 0)
                                    entry["vt_total"]     = sum(stats.values())
                            except Exception:
                                pass
                    elif etype == "file":
                        h = ent.get("Hash", "")
                        if not h or len(h) < 32:
                            continue
                        entry["value"] = f"{ent.get('Name','file')} [{h[:10]}…]"
                        if vt_key:
                            try:
                                r = _rq.get(
                                    f"https://www.virustotal.com/api/v3/files/{h}",
                                    headers={"x-apikey": vt_key}, timeout=8,
                                )
                                if r.status_code == 200:
                                    attrs = r.json().get("data", {}).get("attributes", {})
                                    stats = attrs.get("last_analysis_stats", {})
                                    entry["vt_malicious"] = stats.get("malicious", 0)
                                    entry["vt_total"]     = sum(stats.values())
                            except Exception:
                                pass
                    elif etype in ("url", "dns"):
                        domain = ent.get("URL") or ent.get("Domain", "")
                        if not domain:
                            continue
                        entry["value"] = domain[:60]
                        if vt_key:
                            try:
                                import base64 as _b64
                                enc = _b64.urlsafe_b64encode(domain.encode()).decode().rstrip("=")
                                r = _rq.get(
                                    f"https://www.virustotal.com/api/v3/urls/{enc}",
                                    headers={"x-apikey": vt_key}, timeout=8,
                                )
                                if r.status_code == 200:
                                    attrs = r.json().get("data", {}).get("attributes", {})
                                    stats = attrs.get("last_analysis_stats", {})
                                    entry["vt_malicious"] = stats.get("malicious", 0)
                                    entry["vt_total"]     = sum(stats.values())
                            except Exception:
                                pass
                    else:
                        continue
                    if entry.get("value"):
                        enr_list.append(entry)
                inc["_enrichment_summary"] = enr_list
            except Exception as _ee:
                logger.warning("Email enrichment for #%s failed: %s", num, _ee)

    # 5. Build and send email
    generated_at = _dt.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    summary_dict = {
        "total":      len(ranked),
        "open":       sum(1 for i in ranked if i.get("status") not in ("Closed",)),
        "high_count": sum(1 for i in ranked if i.get("severity") == "High"),
    }
    html_body = _build_incident_email_html(
        incidents=ranked,
        summary=summary_dict,
        days=days,
        app_url=req.app_url.rstrip("/"),
        generated_at=generated_at,
        briefs=briefs,
    )
    subject = (
        f"[Sentinel Vigil] Incident Priority Report — "
        f"{len(ranked)} Active Incidents (Last {days}d)"
    )
    try:
        await _send_graph_mail(req.to, subject, html_body)
    except ValueError as ve:
        raise HTTPException(status_code=503, detail=str(ve))
    except Exception as e:
        logger.error("Graph mail send failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Email send failed: {e}")

    return {
        "sent": True,
        "recipients": req.to,
        "incident_count": len(ranked),
        "subject": subject,
        "llm_briefs": len(briefs),
        "llm_error": llm_brief_error or None,
    }


@router.post("/incidents/{incident_number}/add-enrichment-comment")
async def add_enrichment_comment(incident_number: int, payload: dict = Body(default={})):
    """
    Fetch entities for the incident (from payload or Sentinel), run VT + AbuseIPDB
    enrichment, generate an LLM investigation brief, and post the formatted analysis
    as a comment to the Sentinel incident via the Logic App webhook.
    """
    import asyncio as _aio
    import os as _os
    import requests as _rq
    import html as _html_lib
    from backend.config import settings

    webhook_url = settings.SENTINEL_COMMENT_WEBHOOK_URL
    if not webhook_url:
        raise HTTPException(
            status_code=503,
            detail="SENTINEL_COMMENT_WEBHOOK_URL is not configured. Set this env variable to enable comment posting.",
        )

    entities         = list(payload.get("entities", []))
    incident_title   = str(payload.get("title",    f"Incident #{incident_number}"))
    incident_severity = str(payload.get("severity", "Unknown"))

    # Auto-fetch entities + metadata from Sentinel when none are provided
    if not entities:
        try:
            info_q = (
                f"SecurityIncident | where IncidentNumber == {incident_number}"
                " | summarize arg_max(TimeGenerated, *) by IncidentNumber"
                " | project IncidentName = tostring(column_ifexists('IncidentName','')), Title, Severity | limit 1"
            )
            info_rows = (await run_kql(info_q, days=365)).get("rows", [])
            if info_rows:
                inc_name = str(info_rows[0].get("IncidentName", "")).strip()
                if not incident_title or incident_title == f"Incident #{incident_number}":
                    incident_title = info_rows[0].get("Title", incident_title)
                if incident_severity == "Unknown":
                    incident_severity = info_rows[0].get("Severity", "Unknown")
                if inc_name:
                    entities = await _fetch_arm_entities(inc_name)
        except Exception as _fe:
            logger.warning("Auto-fetch entities for comment failed: %s", _fe)

    # Run enrichment for LLM context (markdown)
    enrichment_md = await _enrich_entities(entities)

    # Run enrichment for HTML display table
    vt_key = _os.environ.get("VIRUSTOTAL_API_KEY", "")
    ab_key = _os.environ.get("ABUSEIPDB_TOKEN", "")
    enr_display: list[dict] = []
    for ent in entities[:12]:
        etype = str(ent.get("type", "")).lower()
        entry: dict = {"type": etype}
        if etype == "ip":
            addr = ent.get("Address", "")
            if not addr:
                continue
            entry["value"] = addr
            if ab_key:
                try:
                    r = _rq.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": addr, "maxAgeInDays": 90},
                        headers={"Key": ab_key, "Accept": "application/json"},
                        timeout=8,
                    )
                    if r.status_code == 200:
                        d = r.json().get("data", {})
                        entry["abuse_score"]   = d.get("abuseConfidenceScore", 0)
                        entry["abuse_country"] = d.get("countryCode", "")
                except Exception:
                    pass
            if vt_key:
                try:
                    r = _rq.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{addr}",
                        headers={"x-apikey": vt_key}, timeout=8,
                    )
                    if r.status_code == 200:
                        attrs = r.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        entry["vt_malicious"]   = stats.get("malicious", 0)
                        entry["vt_suspicious"]  = stats.get("suspicious", 0)
                        entry["vt_total"]       = sum(stats.values())
                        entry["vt_country"]     = attrs.get("country", "")
                except Exception:
                    pass
        elif etype == "file":
            h = ent.get("Hash", "")
            if not h or len(h) < 32:
                continue
            entry["value"] = f"{ent.get('Name','file')} [{h[:12]}…]"
            if vt_key:
                try:
                    r = _rq.get(
                        f"https://www.virustotal.com/api/v3/files/{h}",
                        headers={"x-apikey": vt_key}, timeout=8,
                    )
                    if r.status_code == 200:
                        attrs = r.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        entry["vt_malicious"]    = stats.get("malicious", 0)
                        entry["vt_total"]        = sum(stats.values())
                        entry["vt_threat_label"] = (
                            attrs.get("popular_threat_classification", {})
                                 .get("suggested_threat_label", "")
                        )
                except Exception:
                    pass
        elif etype in ("url", "dns"):
            domain = ent.get("URL") or ent.get("Domain", "")
            if not domain:
                continue
            entry["value"] = domain[:80]
            if vt_key:
                try:
                    import base64 as _b64
                    enc = _b64.urlsafe_b64encode(domain.encode()).decode().rstrip("=")
                    r = _rq.get(
                        f"https://www.virustotal.com/api/v3/urls/{enc}",
                        headers={"x-apikey": vt_key}, timeout=8,
                    )
                    if r.status_code == 200:
                        attrs = r.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        entry["vt_malicious"] = stats.get("malicious", 0)
                        entry["vt_total"]     = sum(stats.values())
                except Exception:
                    pass
        else:
            continue
        if entry.get("value"):
            enr_display.append(entry)

    # Generate LLM investigation brief
    brief = ""
    try:
        brief_system = (
            "You are ARIA, an elite Tier-3 SOC Analyst. Analyze this Sentinel incident and produce "
            "a concise investigation summary with these sections:\n"
            "**Threat Assessment**: 2 sentences on the likely threat scenario\n"
            "**Key Indicators**: Bullet list of the most significant IoCs/entities\n"
            "**Immediate Actions**: Top 3 numbered action items\n"
            "**Risk Level**: One line — Critical/High/Medium/Low with justification\n"
            "Reference entity enrichment data where provided. Use markdown formatting."
        )
        brief_user = (
            f"Incident #{incident_number}: {incident_title}\n"
            f"Severity: {incident_severity}\n"
            f"Entities: {_json_g.dumps([{k: v for k, v in e.items() if k != '_enrichment'} for e in entities[:10]], indent=2)}\n"
            f"{enrichment_md}"
        )
        result = await llm_service.complete(brief_system, brief_user)
        brief = result["text"]
    except Exception as e:
        logger.warning("LLM brief for comment failed: %s", e)
        brief = "LLM analysis unavailable at this time."

    # Build enrichment HTML table
    border   = "#E5E7EB"
    brand    = "#D04A02"
    enr_rows = ""
    for e in enr_display:
        mal   = e.get("vt_malicious", 0)
        vtot  = e.get("vt_total", 0)
        abuse = e.get("abuse_score", 0)
        tlbl  = _html_lib.escape(e.get("vt_threat_label", "") or "—")
        vc    = "#C0392B" if mal > 0 else "#27AE60"
        ac    = "#C0392B" if abuse > 50 else "#E67E22" if abuse > 20 else "#27AE60"
        enr_rows += (
            f'<tr><td style="padding:5px 10px;border-bottom:1px solid {border};font-size:11px;font-family:monospace">{_html_lib.escape(e.get("value",""))}</td>'
            f'<td style="padding:5px 10px;border-bottom:1px solid {border};font-size:11px">{e.get("type","").upper()}</td>'
            f'<td style="padding:5px 10px;border-bottom:1px solid {border};font-size:11px;color:{vc};font-weight:600">{mal}/{vtot} malicious</td>'
            f'<td style="padding:5px 10px;border-bottom:1px solid {border};font-size:11px;color:{ac};font-weight:600">{abuse}/100</td>'
            f'<td style="padding:5px 10px;border-bottom:1px solid {border};font-size:11px">{tlbl}</td></tr>'
        )
    enr_table = ""
    if enr_rows:
        enr_table = (
            f'<h3 style="color:{brand};font-size:13px;font-weight:700;border-bottom:1px solid {border};padding-bottom:6px;margin-top:18px">Threat Intelligence Enrichment</h3>'
            f'<table style="border-collapse:collapse;width:100%;border:1px solid {border};border-radius:6px">'
            f'<thead><tr style="background:#F9FAFB">'
            f'<th style="padding:7px 10px;text-align:left;font-size:10px;font-weight:700;color:#6B7280;text-transform:uppercase">Indicator</th>'
            f'<th style="padding:7px 10px;text-align:left;font-size:10px;font-weight:700;color:#6B7280;text-transform:uppercase">Type</th>'
            f'<th style="padding:7px 10px;text-align:left;font-size:10px;font-weight:700;color:#6B7280;text-transform:uppercase">VirusTotal</th>'
            f'<th style="padding:7px 10px;text-align:left;font-size:10px;font-weight:700;color:#6B7280;text-transform:uppercase">AbuseIPDB</th>'
            f'<th style="padding:7px 10px;text-align:left;font-size:10px;font-weight:700;color:#6B7280;text-transform:uppercase">Threat Label</th>'
            f'</tr></thead><tbody>{enr_rows}</tbody></table>'
        )

    # Convert LLM markdown to basic HTML for Sentinel comment
    def _md_brief_html(text: str) -> str:
        out_lines = []
        for line in text.split("\n"):
            t = line.strip()
            if t.startswith("**") and t.endswith("**"):
                out_lines.append(f'<h4 style="color:{brand};margin:12px 0 4px;font-size:13px">{_html_lib.escape(t.strip("*"))}</h4>')
            elif t.startswith("**") and "**" in t[2:]:
                inner = _re_g.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', _html_lib.escape(t))
                out_lines.append(f'<p style="font-size:12px;margin:4px 0;color:#1F2937">{inner}</p>')
            elif t.startswith("- ") or t.startswith("* "):
                out_lines.append(f'<li style="margin:3px 0;font-size:12px;color:#374151">{_html_lib.escape(t[2:])}</li>')
            elif _re_g.match(r'^\d+\. ', t):
                m = _re_g.match(r'^(\d+)\. (.*)', t)
                if m:
                    out_lines.append(f'<li style="margin:3px 0;font-size:12px;color:#374151">{_html_lib.escape(m.group(2))}</li>')
            elif t:
                out_lines.append(f'<p style="font-size:12px;margin:4px 0;color:#374151">{_html_lib.escape(t)}</p>')
        return "\n".join(out_lines)

    sev_c = {"High": "#C0392B", "Medium": "#E67E22", "Low": "#27AE60"}.get(incident_severity, "#3498DB")
    comment_html = f"""<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:900px">
  <div style="background:linear-gradient(135deg,#1A1E2E,#2D3250);padding:16px 20px;border-radius:8px 8px 0 0">
    <div style="display:flex;align-items:center;gap:10px">
      <span style="font-size:16px">🛡</span>
      <div>
        <div style="color:#FFFFFF;font-size:13px;font-weight:700">Sentinel Vigil — Automated Enrichment Analysis</div>
        <div style="color:#9CA3AF;font-size:11px">Incident #{incident_number} · {_html_lib.escape(incident_title)}</div>
      </div>
      <span style="margin-left:auto;background:{sev_c}33;color:{sev_c};font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px">{_html_lib.escape(incident_severity)}</span>
    </div>
  </div>
  <div style="border:1px solid {border};border-top:none;border-radius:0 0 8px 8px;padding:18px 20px">
    {_md_brief_html(brief)}
    {enr_table}
    <div style="margin-top:16px;padding-top:12px;border-top:1px solid {border};font-size:10px;color:#9CA3AF">
      Auto-generated by Sentinel Vigil · VT + AbuseIPDB enrichment · Claude AI analysis
    </div>
  </div>
</div>"""

    # POST to Logic App webhook
    def _post_webhook():
        return _rq.post(
            webhook_url,
            json={"incidentId": str(incident_number), "message": comment_html},
            timeout=30,
        )

    loop = _aio.get_event_loop()
    try:
        resp = await loop.run_in_executor(None, _post_webhook)
        if not resp.ok:
            raise HTTPException(
                status_code=502,
                detail=f"Webhook returned HTTP {resp.status_code}: {resp.text[:300]}",
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Enrichment comment webhook failed: %s", e)
        raise HTTPException(status_code=502, detail=f"Webhook error: {e}")

    return {
        "success": True,
        "message": f"Enrichment analysis posted as comment to incident #{incident_number}",
    }


@router.post("/incidents/{incident_number}/post-comment")
async def post_incident_comment_plain(incident_number: int, payload: dict = Body(default={})):
    """Post a plain-text comment to a Sentinel incident (used by the standalone comment form)."""
    import asyncio as _aio
    import requests as _rq
    from backend.config import settings

    webhook_url = settings.SENTINEL_COMMENT_WEBHOOK_URL
    if not webhook_url:
        raise HTTPException(status_code=503, detail="SENTINEL_COMMENT_WEBHOOK_URL is not configured")

    message = str(payload.get("message", "")).strip()
    if not message:
        raise HTTPException(status_code=400, detail="Comment message cannot be empty")

    def _call():
        return _rq.post(
            webhook_url,
            json={"incidentId": str(incident_number), "message": message},
            timeout=30,
        )

    loop = _aio.get_event_loop()
    try:
        resp = await loop.run_in_executor(None, _call)
        if not resp.ok:
            raise HTTPException(status_code=502, detail=f"Webhook returned {resp.status_code}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Webhook error: {e}")

    return {"success": True}


@router.get("/incidents/{incident_number}/comment-form", response_class=HTMLResponse)
async def incident_comment_form_page(incident_number: int):
    """Standalone HTML comment form — linked from incident report emails."""
    content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Add Comment — Incident #{incident_number}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#F3F4F6;margin:0;padding:24px}}
  .card{{background:#fff;border-radius:10px;padding:28px;max-width:540px;margin:0 auto;box-shadow:0 2px 16px rgba(0,0,0,0.08)}}
  h2{{color:#D04A02;margin:0 0 6px;font-size:18px}} .sub{{color:#6B7280;font-size:13px;margin-bottom:20px}}
  textarea{{width:100%;height:150px;border:1px solid #D1D5DB;border-radius:8px;padding:12px;font-size:13px;resize:vertical;box-sizing:border-box;outline:none}}
  textarea:focus{{border-color:#D04A02;box-shadow:0 0 0 3px rgba(208,74,2,0.1)}}
  button{{background:#D04A02;color:#fff;border:none;padding:10px 24px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;margin-top:12px}}
  button:hover{{background:#B84201}} button:disabled{{background:#9CA3AF;cursor:default}}
  .ok{{background:#D1FAE5;border:1px solid #6EE7B7;border-radius:8px;padding:14px;color:#065F46;margin-top:12px;display:none;font-size:13px}}
  .err{{background:#FEE2E2;border:1px solid #FECACA;border-radius:8px;padding:14px;color:#991B1B;margin-top:12px;display:none;font-size:13px}}
</style></head>
<body><div class="card">
  <h2>🛡 Add Comment</h2>
  <div class="sub">Incident #{incident_number} · Microsoft Sentinel via Sentinel Vigil</div>
  <form id="f">
    <textarea id="msg" placeholder="Enter your investigation notes, findings, or actions taken…" required></textarea>
    <button type="submit" id="btn">Post Comment to Sentinel</button>
  </form>
  <div class="ok" id="ok">✅ Comment posted to Sentinel incident #{incident_number}</div>
  <div class="err" id="err"></div>
</div>
<script>
document.getElementById('f').onsubmit=async function(e){{
  e.preventDefault();
  const msg=document.getElementById('msg').value.trim();
  if(!msg)return;
  const btn=document.getElementById('btn');
  btn.disabled=true;btn.textContent='Posting…';
  try{{
    const res=await fetch('/api/incident-analytics/incidents/{incident_number}/post-comment',{{
      method:'POST',headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{message:msg}})
    }});
    const data=await res.json();
    if(res.ok){{document.getElementById('ok').style.display='block';document.getElementById('f').style.display='none'}}
    else{{document.getElementById('err').textContent='❌ '+(data.detail||'Failed');document.getElementById('err').style.display='block';btn.disabled=false;btn.textContent='Post Comment to Sentinel'}}
  }}catch(ex){{document.getElementById('err').textContent='❌ Network error: '+ex.message;document.getElementById('err').style.display='block';btn.disabled=false;btn.textContent='Post Comment to Sentinel'}}
}};
</script></body></html>"""
    return HTMLResponse(content=content)


@router.get("/incidents/{incident_number}/enrich-comment-confirm", response_class=HTMLResponse)
async def enrich_comment_confirm_page(incident_number: int):
    """Confirmation page — linked from emails — to trigger enrichment + AI comment posting."""
    content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Add Enrichment Analysis — Incident #{incident_number}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#F3F4F6;margin:0;padding:24px}}
  .card{{background:#fff;border-radius:10px;padding:28px;max-width:540px;margin:0 auto;box-shadow:0 2px 16px rgba(0,0,0,0.08)}}
  h2{{color:#D04A02;margin:0 0 6px;font-size:18px}} .sub{{color:#6B7280;font-size:13px;margin-bottom:16px}}
  .info{{background:rgba(208,74,2,0.05);border:1px solid rgba(208,74,2,0.2);border-left:3px solid #D04A02;border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:13px;color:#374151;line-height:1.6}}
  button{{background:#1E40AF;color:#fff;border:none;padding:12px 28px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer}}
  button:hover{{background:#1D3EA0}} button:disabled{{background:#9CA3AF;cursor:default}}
  .prog{{font-size:13px;color:#6B7280;margin-top:14px;display:none}}
  .ok{{background:#D1FAE5;border:1px solid #6EE7B7;border-radius:8px;padding:14px;color:#065F46;margin-top:16px;display:none;font-size:13px}}
  .err{{background:#FEE2E2;border:1px solid #FECACA;border-radius:8px;padding:14px;color:#991B1B;margin-top:16px;display:none;font-size:13px}}
</style></head>
<body><div class="card">
  <h2>🧠 Add Enrichment Analysis as Comment</h2>
  <div class="sub">Incident #{incident_number} · Sentinel Vigil Automated Analysis</div>
  <div class="info">
    This action will:<br>
    • Fetch entities (IPs, domains, file hashes) for incident #{incident_number}<br>
    • Run VirusTotal &amp; AbuseIPDB enrichment checks on all indicators<br>
    • Generate a Tier-3 AI investigation brief via Claude<br>
    • Post the full analysis as a formatted comment in Microsoft Sentinel
  </div>
  <button id="btn" onclick="go()">Confirm &amp; Post Analysis</button>
  <div class="prog" id="prog">⏳ Fetching entities, running enrichment &amp; generating AI brief… (15–30 seconds)</div>
  <div class="ok" id="ok"></div>
  <div class="err" id="err"></div>
</div>
<script>
async function go(){{
  const btn=document.getElementById('btn');
  btn.disabled=true;btn.textContent='Processing…';
  document.getElementById('prog').style.display='block';
  try{{
    const res=await fetch('/api/incident-analytics/incidents/{incident_number}/add-enrichment-comment',{{
      method:'POST',headers:{{'Content-Type':'application/json'}},body:'{{}}'
    }});
    const data=await res.json();
    document.getElementById('prog').style.display='none';
    if(res.ok){{document.getElementById('ok').textContent='✅ '+(data.message||'Analysis posted as Sentinel comment');document.getElementById('ok').style.display='block';btn.style.display='none'}}
    else{{document.getElementById('err').textContent='❌ '+(data.detail||'Failed');document.getElementById('err').style.display='block';btn.disabled=false;btn.textContent='Retry'}}
  }}catch(ex){{document.getElementById('prog').style.display='none';document.getElementById('err').textContent='❌ Network error: '+ex.message;document.getElementById('err').style.display='block';btn.disabled=false;btn.textContent='Retry'}}
}}
</script></body></html>"""
    return HTMLResponse(content=content)
