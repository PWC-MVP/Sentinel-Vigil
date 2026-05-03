"""
Sign-in GeoMap router.
POST /api/geomap/query    → run KQL, enrich IPs, return geo+intel data
GET  /api/geomap/reports  → list generated geomap HTML reports
POST /api/geomap/generate → generate standalone geomap HTML file
"""
import json
import logging
import asyncio
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.services import sentinel as sentinel_svc
from backend.config import settings

router = APIRouter(prefix="/api/geomap", tags=["geomap"])
logger = logging.getLogger(__name__)
ROOT = Path(__file__).parent.parent.parent


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class GeoMapRequest(BaseModel):
    query_type: str = "failed"   # failed | all | risky | mfa
    days: int = 7
    max_ips: int = 50


class GeoMapGenerateRequest(BaseModel):
    data: list[dict]
    title: str = "Sign-in Geographic Analysis"
    days: int = 7


# ── KQL templates ────────────────────────────────────────────────────────────

GEOMAP_KQL = {
    "failed": """SigninLogs
| where TimeGenerated > ago({days}d)
| where ResultType != 0
| where IPAddress != "127.0.0.1"
| extend
    _lat = toreal(LocationDetails.geoCoordinates.latitude),
    _lon = toreal(LocationDetails.geoCoordinates.longitude),
    _city = tostring(LocationDetails.city),
    _state = tostring(LocationDetails.state),
    _country = tostring(LocationDetails.countryOrRegion)
| summarize
    value = count(),
    unique_users = dcount(UserPrincipalName),
    latest_time = max(TimeGenerated),
    lat = avgif(_lat, isnotnull(_lat)),
    lon = avgif(_lon, isnotnull(_lon)),
    city = anyif(_city, isnotempty(_city)),
    state = anyif(_state, isnotempty(_state)),
    country = anyif(_country, isnotempty(_country))
    by ip = IPAddress
| order by value desc
| take {max_ips}""",

    "all": """SigninLogs
| where TimeGenerated > ago({days}d)
| where IPAddress != "127.0.0.1"
| extend
    _lat = toreal(LocationDetails.geoCoordinates.latitude),
    _lon = toreal(LocationDetails.geoCoordinates.longitude),
    _city = tostring(LocationDetails.city),
    _state = tostring(LocationDetails.state),
    _country = tostring(LocationDetails.countryOrRegion)
| summarize
    value = count(),
    success_count = countif(ResultType == 0),
    failed_count = countif(ResultType != 0),
    unique_users = dcount(UserPrincipalName),
    lat = avgif(_lat, isnotnull(_lat)),
    lon = avgif(_lon, isnotnull(_lon)),
    city = anyif(_city, isnotempty(_city)),
    state = anyif(_state, isnotempty(_state)),
    country = anyif(_country, isnotempty(_country))
    by ip = IPAddress
| where value > 1
| order by value desc
| take {max_ips}""",

    "risky": """SigninLogs
| where TimeGenerated > ago({days}d)
| where RiskState in ("atRisk", "confirmedCompromised")
| extend
    _lat = toreal(LocationDetails.geoCoordinates.latitude),
    _lon = toreal(LocationDetails.geoCoordinates.longitude),
    _city = tostring(LocationDetails.city),
    _state = tostring(LocationDetails.state),
    _country = tostring(LocationDetails.countryOrRegion)
| summarize
    value = count(),
    risk_state = any(RiskState),
    unique_users = dcount(UserPrincipalName),
    lat = avgif(_lat, isnotnull(_lat)),
    lon = avgif(_lon, isnotnull(_lon)),
    city = anyif(_city, isnotempty(_city)),
    state = anyif(_state, isnotempty(_state)),
    country = anyif(_country, isnotempty(_country))
    by ip = IPAddress
| order by value desc
| take {max_ips}""",

    "mfa": """SigninLogs
| where TimeGenerated > ago({days}d)
| where ResultType == 500127
| where IPAddress != "127.0.0.1"
| extend
    _lat = toreal(LocationDetails.geoCoordinates.latitude),
    _lon = toreal(LocationDetails.geoCoordinates.longitude),
    _city = tostring(LocationDetails.city),
    _state = tostring(LocationDetails.state),
    _country = tostring(LocationDetails.countryOrRegion)
| summarize
    value = count(),
    unique_users = dcount(UserPrincipalName),
    latest_time = max(TimeGenerated),
    lat = avgif(_lat, isnotnull(_lat)),
    lon = avgif(_lon, isnotnull(_lon)),
    city = anyif(_city, isnotempty(_city)),
    state = anyif(_state, isnotempty(_state)),
    country = anyif(_country, isnotempty(_country))
    by ip = IPAddress
| order by value desc
| take {max_ips}""",
}

QUERY_LABELS = {
    "failed": "Failed Sign-in Origins",
    "all": "All Sign-in Locations",
    "risky": "Risky Sign-in IPs",
    "mfa": "MFA Failure Locations",
}


@router.post("/query")
async def geomap_query(req: GeoMapRequest):
    """
    1. Run KQL to get IP + count from SigninLogs
    2. Enrich IPs with geo+intel (ipinfo, AbuseIPDB, vpnapi)
    3. Return combined data ready for Leaflet rendering
    """
    try:
        q_type = req.query_type if req.query_type in GEOMAP_KQL else "failed"
        kql = GEOMAP_KQL[q_type].format(days=req.days, max_ips=req.max_ips)

        # Run KQL
        logger.info(f"Running Geomap KQL query type: {q_type}")
        try:
            kql_result = await sentinel_svc.run_kql(kql, days=req.days)
        except Exception as kql_err:
            logger.error(f"Geomap KQL failed: {kql_err}")
            raise HTTPException(status_code=500, detail=f"Sentinel KQL failed: {str(kql_err)}")

        rows = kql_result.get("rows", [])

        if not rows:
            return {
                "points": [],
                "title": QUERY_LABELS[q_type],
                "query_type": q_type,
                "days": req.days,
                "message": "No data returned from Sentinel. The workspace may be empty or credentials may need refresh.",
            }

        ips = [str(r.get("ip", r.get("IPAddress", ""))) for r in rows if r.get("ip") or r.get("IPAddress")]
        value_map = {str(r.get("ip", r.get("IPAddress", ""))): int(r.get("value", 1)) for r in rows}

        # Build sentinel-native geo map from LocationDetails extracted in KQL
        sentinel_geo_map: dict[str, dict] = {}
        for r in rows:
            ip = str(r.get("ip", r.get("IPAddress", "")))
            if not ip:
                continue
            lat = r.get("lat")
            lon = r.get("lon")
            try:
                lat = float(lat) if lat is not None else None
                lon = float(lon) if lon is not None else None
            except (TypeError, ValueError):
                lat = lon = None
            if lat is not None and lon is not None and not (lat == 0.0 and lon == 0.0):
                sentinel_geo_map[ip] = {
                    "lat": lat, "lon": lon,
                    "city": r.get("city") or "",
                    "region": r.get("state") or "",
                    "country": r.get("country") or "",
                }

        # Attempt external IP enrichment for threat intel (best-effort)
        import sys
        sys.path.insert(0, str(ROOT))
        enriched_map: dict[str, dict] = {}
        try:
            import enrich_ips as enrich_module  # type: ignore
            loop = asyncio.get_event_loop()
            enriched_list = await asyncio.wait_for(
                loop.run_in_executor(
                    None, lambda: enrich_module.enrich_ips(ips[:req.max_ips], max_workers=20)
                ),
                timeout=90.0,
            )
            enriched_map = {e["ip"]: e for e in enriched_list if e.get("ip")}
        except asyncio.TimeoutError:
            logger.warning("IP enrichment timed out after 90s — using Sentinel geo only")
        except Exception as e:
            logger.warning("IP enrichment failed — using Sentinel geo only: %s", e)

        # Build geo points — prefer enrichment coords, fall back to Sentinel LocationDetails
        points = []
        for ip in ips:
            enriched = enriched_map.get(ip, {})
            sentinel_geo = sentinel_geo_map.get(ip, {})

            lat = enriched.get("lat") or enriched.get("latitude") or sentinel_geo.get("lat")
            lon = enriched.get("lon") or enriched.get("longitude") or sentinel_geo.get("lon")
            if lat is None or lon is None:
                continue  # no coordinates from either source

            value = value_map.get(ip, 1)
            points.append({
                "ip": ip,
                "lat": float(lat),
                "lon": float(lon),
                "value": value,
                "city": enriched.get("city") or sentinel_geo.get("city"),
                "region": enriched.get("region") or sentinel_geo.get("region"),
                "country": enriched.get("country") or sentinel_geo.get("country"),
                "org": enriched.get("org"),
                "asn": enriched.get("asn"),
                "is_vpn": enriched.get("is_vpn", False),
                "is_tor": enriched.get("is_tor", False),
                "is_proxy": enriched.get("is_proxy", False),
                "abuse_score": enriched.get("abuse_confidence_score", 0),
                "threat_detected": enriched.get("threat_detected", False),
                "threat_description": enriched.get("threat_description"),
            })

        points.sort(key=lambda p: p["value"], reverse=True)

        result: dict = {
            "points": points,
            "title": QUERY_LABELS[q_type],
            "query_type": q_type,
            "days": req.days,
            "total_ips_queried": len(ips),
            "ips_geocoded": len(points),
            "countries": len(set(p["country"] for p in points if p.get("country"))),
            "max_value": max((p["value"] for p in points), default=1),
        }
        if not points and ips:
            result["message"] = (
                f"Sentinel returned {len(ips)} IPs but none had geolocation data. "
                "LocationDetails may be empty in SigninLogs, and external enrichment is unavailable."
            )
        return result
    except Exception as e:
        logger.error(f"Unexpected error in geomap_query: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate")
async def generate_geomap_html(req: GeoMapGenerateRequest):
    """Generate a standalone geomap HTML file from provided data."""
    from datetime import datetime
    reports_dir = settings.OUTPUT_DIR
    reports_dir.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"SigninLogs_Geomap_{ts}.html"
    out_path = reports_dir / filename

    html = _build_geomap_html(req.data, req.title, req.days)
    out_path.write_text(html, encoding="utf-8")

    return {
        "filename": filename,
        "path": str(out_path),
        "size_bytes": out_path.stat().st_size,
        "points": len(req.data),
    }


@router.get("/reports")
async def list_geomap_reports():
    """List existing geomap HTML files."""
    reports_dir = settings.OUTPUT_DIR
    if not reports_dir.exists():
        return {"reports": []}
    files = []
    for f in reports_dir.glob("SigninLogs_*Geomap*.html"):
        files.append({
            "name": f.name,
            "size_bytes": f.stat().st_size,
            "created": f.stat().st_mtime,
            "relative_path": f.name,
        })
    files.sort(key=lambda x: x["created"], reverse=True)
    return {"reports": files}


# ── HTML template for exported geomap ────────────────────────────────────────

def _build_geomap_html(data: list[dict], title: str, days: int) -> str:
    data_json = json.dumps(data, default=str)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css"/>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Segoe UI', sans-serif; background:#F7F7F7; }}
  .layout {{ display:flex; height:100vh; }}
  .sidebar {{ width:320px; background:#fff; border-right:3px solid #D04A02; overflow-y:auto; display:flex; flex-direction:column; }}
  .sidebar-header {{ background:#D04A02; color:#fff; padding:20px; }}
  .sidebar-header h1 {{ font-size:16px; font-weight:700; }}
  .sidebar-header p {{ font-size:11px; opacity:.85; margin-top:4px; }}
  .stats-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:8px; padding:14px; }}
  .stat-card {{ background:#FFF0E8; border:1px solid rgba(208,74,2,.2); border-radius:6px; padding:10px; text-align:center; }}
  .stat-val {{ font-size:20px; font-weight:800; color:#D04A02; }}
  .stat-lbl {{ font-size:10px; color:#666; margin-top:2px; text-transform:uppercase; }}
  .ip-list {{ flex:1; overflow-y:auto; padding:0 14px 14px; }}
  .ip-list h3 {{ font-size:11px; font-weight:700; text-transform:uppercase; color:#999; margin:10px 0 6px; letter-spacing:.06em; }}
  .ip-item {{ background:#F7F7F7; border:1px solid #E5E5E5; border-radius:6px; padding:10px; margin-bottom:6px; cursor:pointer; transition:all .15s; border-left:3px solid #D04A02; }}
  .ip-item:hover {{ box-shadow:0 2px 8px rgba(0,0,0,.1); transform:translateX(2px); }}
  .ip-item.threat {{ border-left-color:#C0392B; background:#FFF5F5; }}
  .ip-addr {{ font-family:monospace; font-size:13px; font-weight:600; color:#2D2D2D; }}
  .ip-loc {{ font-size:11px; color:#666; margin-top:2px; }}
  .ip-badges {{ display:flex; gap:4px; flex-wrap:wrap; margin-top:5px; }}
  .badge {{ font-size:10px; font-weight:600; padding:1px 7px; border-radius:20px; }}
  .badge-red {{ background:#FCEAEA; color:#C0392B; border:1px solid rgba(192,57,43,.2); }}
  .badge-orange {{ background:#FEF3E8; color:#E67E22; border:1px solid rgba(230,126,34,.2); }}
  .badge-grey {{ background:#F0F0F0; color:#666; border:1px solid #DDD; }}
  .map-area {{ flex:1; position:relative; }}
  #map {{ width:100%; height:100%; }}
  .legend {{ position:absolute; bottom:20px; right:20px; z-index:1000; background:#fff; border:1px solid #E5E5E5; border-radius:8px; padding:14px; font-size:12px; box-shadow:0 2px 12px rgba(0,0,0,.1); min-width:180px; }}
  .legend h3 {{ font-size:11px; font-weight:700; color:#D04A02; text-transform:uppercase; margin-bottom:10px; }}
  .legend-item {{ display:flex; align-items:center; margin-bottom:6px; gap:8px; }}
  .lc {{ width:14px; height:14px; border-radius:50%; }}
  .footer-bar {{ position:absolute; bottom:0; left:0; right:0; background:#2D2D2D; color:rgba(255,255,255,.7); font-size:11px; padding:6px 16px; text-align:center; z-index:999; }}
</style>
</head>
<body>
<div class="layout">
  <div class="sidebar">
    <div class="sidebar-header">
      <h1>🗺️ {title}</h1>
      <p>Last {days} days · Generated {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    </div>
    <div class="stats-grid" id="stats"></div>
    <div class="ip-list">
      <h3>Top IPs by Activity</h3>
      <div id="ip-list-items"></div>
    </div>
  </div>
  <div class="map-area">
    <div id="map"></div>
    <div class="legend">
      <h3>Activity Level</h3>
      <div class="legend-item"><div class="lc" style="background:#C0392B"></div><span>High (50+)</span></div>
      <div class="legend-item"><div class="lc" style="background:#E67E22"></div><span>Medium (10–50)</span></div>
      <div class="legend-item"><div class="lc" style="background:#27AE60"></div><span>Low (1–10)</span></div>
      <div class="legend-item"><div class="lc" style="background:#C0392B; border:2px solid #8B0000"></div><span>Threat Intel Match</span></div>
    </div>
    <div class="footer-bar">🛡️ Created by Sentinel Engineering Team · PwC Sentinel Vigil</div>
  </div>
</div>
<script>
const GEO_DATA = {data_json};

const map = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
  attribution: '© OpenStreetMap contributors', maxZoom: 19
}}).addTo(map);

const maxVal = Math.max(...GEO_DATA.map(p => p.value), 1);

function markerColor(p) {{
  if (p.threat_detected) return '#C0392B';
  const ratio = p.value / maxVal;
  if (ratio > 0.5) return '#C0392B';
  if (ratio > 0.15) return '#E67E22';
  return '#27AE60';
}}

const markers = [];
GEO_DATA.forEach(p => {{
  const r = 10 + (p.value / maxVal) * 28;
  const color = markerColor(p);
  const m = L.circleMarker([p.lat, p.lon], {{
    radius: r, fillColor: color, color: '#fff', weight: 2, opacity: 1, fillOpacity: 0.75
  }}).addTo(map);

  const flags = [
    p.threat_detected ? '<span class="badge badge-red">THREAT</span>' : '',
    p.is_vpn ? '<span class="badge badge-grey">VPN</span>' : '',
    p.is_tor ? '<span class="badge badge-red">TOR</span>' : '',
    (p.abuse_score || 0) > 50 ? `<span class="badge badge-orange">ABUSE ${{p.abuse_score}}%</span>` : '',
  ].filter(Boolean).join(' ');

  m.bindPopup(`
    <div style="font-size:12px;min-width:180px">
      <strong style="font-family:monospace">${{p.ip}}</strong><br>
      📍 ${{[p.city, p.region, p.country].filter(Boolean).join(', ') || 'Unknown'}}<br>
      🏢 ${{p.org || p.asn || 'Unknown'}}<br>
      🔢 ${{p.value}} sign-in attempts<br>
      ${{flags ? `<div style="margin-top:5px">${{flags}}</div>` : ''}}
    </div>
  `);
  markers.push(p);
}});

if (markers.length > 0) {{
  const bounds = GEO_DATA.map(p => [p.lat, p.lon]);
  map.fitBounds(bounds, {{ padding: [40, 40] }});
}}

// Stats
const statsEl = document.getElementById('stats');
const countries = new Set(GEO_DATA.map(p => p.country).filter(Boolean));
const threats = GEO_DATA.filter(p => p.threat_detected).length;
const totalVal = GEO_DATA.reduce((s, p) => s + p.value, 0);
statsEl.innerHTML = `
  <div class="stat-card"><div class="stat-val">${{GEO_DATA.length}}</div><div class="stat-lbl">IPs</div></div>
  <div class="stat-card"><div class="stat-val">${{countries.size}}</div><div class="stat-lbl">Countries</div></div>
  <div class="stat-card"><div class="stat-val" style="color:${{threats>0?'#C0392B':'#27AE60'}}">${{threats}}</div><div class="stat-lbl">Threats</div></div>
  <div class="stat-card"><div class="stat-val">${{totalVal.toLocaleString()}}</div><div class="stat-lbl">Total</div></div>
`;

// IP list
const listEl = document.getElementById('ip-list-items');
GEO_DATA.slice(0, 20).forEach(p => {{
  const div = document.createElement('div');
  div.className = 'ip-item' + (p.threat_detected ? ' threat' : '');
  const flags = [
    p.threat_detected ? '<span class="badge badge-red">THREAT</span>' : '',
    p.is_vpn ? '<span class="badge badge-grey">VPN</span>' : '',
    p.is_tor ? '<span class="badge badge-red">TOR</span>' : '',
  ].filter(Boolean).join('');
  div.innerHTML = `
    <div class="ip-addr">${{p.ip}} <span style="font-size:11px;color:#999;font-family:sans-serif">${{p.value}} attempts</span></div>
    <div class="ip-loc">📍 ${{[p.city, p.country].filter(Boolean).join(', ') || 'Unknown'}}</div>
    ${{flags ? `<div class="ip-badges">${{flags}}</div>` : ''}}
  `;
  div.onclick = () => map.setView([p.lat, p.lon], 8);
  listEl.appendChild(div);
}});
</script>
</body>
</html>"""
