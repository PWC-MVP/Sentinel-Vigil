from collections import defaultdict
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from backend.services.sentinel import run_kql
from backend.services import llm as llm_service
import logging

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


@router.get("/mttr")
async def get_mttr(days: int = Query(30)):
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
async def get_incident_trends(days: int = Query(30)):
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
async def get_incident_owners(days: int = Query(30)):
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
async def get_sla_compliance(days: int = Query(30)):
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
async def get_incident_summary(days: int = Query(30)):
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
async def get_incidents(days: int = Query(30)):
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
async def get_recurrence(days: int = Query(30)):
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


@router.post("/analyze-incident")
async def analyze_single_incident(payload: dict):
    """Analyze a single incident with LLM and return targeted recommendations."""
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
        "confirmed threat-intel matches for domains or file hashes, and how these affect the risk assessment.\n\n"
        "Use markdown formatting with clear headings. Always include a summary table. "
        "Be direct, evidence-based, and actionable."
    )

    closed_str = inc.get("closed", "") or "Not yet closed"
    mttr = inc.get("mttr_hours", 0) or 0

    # Run entity enrichment in parallel with prompt assembly
    enrichment_section = await _enrich_entities(raw_entities)

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
        f"{enrichment_section}\n\n"
        "Provide a thorough analysis with actionable recommendations."
    )

    try:
        result = await llm_service.complete(system, user_msg)
        return {"analysis": result["text"], "usage": result.get("usage", {})}
    except Exception as e:
        logger.error("Per-incident analysis failed: %s", e)
        raise HTTPException(status_code=500, detail=f"LLM analysis failed: {str(e)}")


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
