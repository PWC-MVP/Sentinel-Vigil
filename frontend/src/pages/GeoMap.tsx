import { useState, useEffect, useRef } from 'react';
import { http as axios } from '../api/client';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// ── Types ─────────────────────────────────────────────────────────────────────
interface GeoPoint {
    ip: string;
    lat: number;
    lon: number;
    value: number;
    city?: string;
    region?: string;
    country?: string;
    org?: string;
    is_vpn?: boolean;
    is_tor?: boolean;
    abuse_score?: number;
    threat_detected?: boolean;
    threat_description?: string;
}
interface GeoResult {
    points?: GeoPoint[];
    title?: string;
    query_type?: string;
    days?: number;
    total_ips_queried?: number;
    ips_geocoded?: number;
    countries?: number;
    max_value?: number;
    message?: string;
}

const QUERY_TYPES = [
    { id: 'failed', label: '🔴 Failed Sign-ins', desc: 'Attack origin mapping (ResultType ≠ 0)' },
    { id: 'all', label: '🌍 All Sign-ins', desc: 'Global usage distribution' },
    { id: 'risky', label: '⚠️ Risky Sign-ins', desc: 'Identity Protection (atRisk / confirmedCompromised)' },
    { id: 'mfa', label: '🔑 MFA Failures', desc: 'MFA attack locations (ResultType 500127)' },
];

function markerColor(p: GeoPoint, maxVal: number) {
    if (p.threat_detected) return '#C0392B';
    const r = p.value / maxVal;
    if (r > 0.5) return '#C0392B';
    if (r > 0.15) return '#E67E22';
    return '#27AE60';
}

export default function GeoMap() {
    const [queryType, setQueryType] = useState('failed');
    const [days, setDays] = useState(7);
    const [loading, setLoading] = useState(false);
    const [data, setData] = useState<GeoResult | null>(null);
    const [selectedIp, setSelectedIp] = useState<GeoPoint | null>(null);
    const [generating, setGenerating] = useState(false);
    const [genMsg, setGenMsg] = useState('');
    const mapContainerRef = useRef<HTMLDivElement>(null);
    const leafletMapRef = useRef<any>(null);
    const markersRef = useRef<any[]>([]);

    // Init map once
    useEffect(() => {
        if (!mapContainerRef.current || leafletMapRef.current) return;
        const map = L.map(mapContainerRef.current).setView([20, 0], 2);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap', maxZoom: 19,
        }).addTo(map);
        leafletMapRef.current = map;
    }, []);

    // Update markers when data changes
    useEffect(() => {
        const map = leafletMapRef.current;
        if (!map) return;

        // Remove old markers
        markersRef.current.forEach(m => map.removeLayer(m));
        markersRef.current = [];

        const points = data?.points || [];
        if (points.length === 0) return;

        const maxVal = data?.max_value || Math.max(...points.map(p => p.value), 1);

        points.forEach(p => {
            const r = 10 + (p.value / maxVal) * 26;
            const color = markerColor(p, maxVal);

            const circle = L.circleMarker([p.lat, p.lon], {
                radius: r, fillColor: color, color: '#fff', weight: 2, opacity: 1, fillOpacity: 0.75,
            }).addTo(map);

            const flags = [
                p.threat_detected ? '<span style="background:#FCEAEA;color:#C0392B;padding:1px 6px;border-radius:10px;font-size:10px;font-weight:700">THREAT</span>' : '',
                p.is_vpn ? '<span style="background:#F0F0F0;color:#666;padding:1px 6px;border-radius:10px;font-size:10px">VPN</span>' : '',
                p.is_tor ? '<span style="background:#FCEAEA;color:#C0392B;padding:1px 6px;border-radius:10px;font-size:10px">TOR</span>' : '',
                (p.abuse_score || 0) > 50 ? `<span style="background:#FEF3E8;color:#E67E22;padding:1px 6px;border-radius:10px;font-size:10px">ABUSE ${p.abuse_score}%</span>` : '',
            ].filter(Boolean).join(' ');

            circle.bindPopup(`
        <div style="font-size:12px;min-width:180px;font-family:Inter,sans-serif">
          <strong style="font-family:monospace">${p.ip}</strong><br/>
          📍 ${[p.city, p.region, p.country].filter(Boolean).join(', ') || 'Unknown'}<br/>
          🏢 ${p.org || 'Unknown'}<br/>
          🔢 ${p.value} sign-in attempts<br/>
          ${flags ? `<div style="margin-top:5px;display:flex;gap:4px;flex-wrap:wrap">${flags}</div>` : ''}
        </div>
      `);

            circle.on('click', () => setSelectedIp(p));
            markersRef.current.push(circle);
        });

        if (points.length > 0) {
            const bounds = points.map(p => [p.lat, p.lon]);
            map.fitBounds(bounds as any, { padding: [40, 40] });
        }
    }, [data]);

    const handleQuery = async () => {
        setLoading(true);
        setSelectedIp(null);
        try {
            const r = await axios.post('/api/geomap/query', {
                query_type: queryType, days, max_ips: 80,
            }, { timeout: 120000 });
            setData(r.data);
        } catch (e: any) {
            setData({ message: `Error: ${e.response?.data?.detail || e.message}` });
        } finally {
            setLoading(false);
        }
    };

    const handleExport = async () => {
        if (!data?.points?.length) return;
        setGenerating(true);
        setGenMsg('');
        try {
            const r = await axios.post('/api/geomap/generate', {
                data: data.points, title: data.title, days,
            });

            // Trigger download via reports endpoint
            const filename = r.data.filename;
            const a = document.createElement('a');
            a.href = `/api/reports/${filename}`;
            a.download = filename;
            a.click();

            setGenMsg(`✓ Export successful! Downloaded ${filename}`);
        } catch (e: any) {
            setGenMsg(`Error: ${e.message}`);
        } finally {
            setGenerating(false);
        }
    };

    const points = data?.points || [];
    const threats = points.filter(p => p.threat_detected);

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
            {/* Header */}
            <div className="page-header" style={{ flexShrink: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                        <div className="page-title">🗺️ Sign-in GeoMap</div>
                        <div className="page-subtitle">Interactive world map of sign-in origin IPs, enriched with threat intelligence</div>
                    </div>
                    {points.length > 0 && (
                        <button className="btn btn-outline btn-sm" onClick={handleExport} disabled={generating}>
                            {generating ? '⏳ Saving…' : '💾 Export HTML Map'}
                        </button>
                    )}
                </div>
                {genMsg && (
                    <div style={{ marginTop: 8, fontSize: 12, color: 'var(--pwc-orange)', background: 'var(--pwc-orange-light)', padding: '6px 12px', borderRadius: 4 }}>
                        {genMsg}
                    </div>
                )}
            </div>

            {/* Controls */}
            <div style={{ padding: '12px 28px', background: 'var(--pwc-white)', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                    <div style={{ display: 'flex', gap: 6 }}>
                        {QUERY_TYPES.map(qt => (
                            <button
                                key={qt.id}
                                onClick={() => setQueryType(qt.id)}
                                className={`btn btn-sm ${queryType === qt.id ? 'btn-primary' : 'btn-secondary'}`}
                                title={qt.desc}
                            >
                                {qt.label}
                            </button>
                        ))}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Days:</span>
                        {[7, 14, 30].map(d => (
                            <button key={d} onClick={() => setDays(d)} className={`btn btn-sm ${days === d ? 'btn-outline' : 'btn-ghost'}`}>
                                {d}d
                            </button>
                        ))}
                    </div>
                    <button className="btn btn-primary" onClick={handleQuery} disabled={loading} style={{ marginLeft: 'auto' }}>
                        {loading ? <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Querying…</> : '🔍 Run Analysis'}
                    </button>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
                    {QUERY_TYPES.find(q => q.id === queryType)?.desc}
                </div>
            </div>

            {/* Stat bar */}
            {data && points.length > 0 && (
                <div style={{ padding: '8px 28px', background: 'var(--pwc-pale-grey)', borderBottom: '1px solid var(--border)', display: 'flex', gap: 24, fontSize: 12, flexShrink: 0 }}>
                    <span>📍 <strong>{data.ips_geocoded}</strong> geocoded IPs</span>
                    <span>🌍 <strong>{data.countries}</strong> countries</span>
                    {threats.length > 0 && <span style={{ color: 'var(--critical)' }}>⚠️ <strong>{threats.length}</strong> threat intel matches</span>}
                    <span className="text-muted">Total: {data.total_ips_queried} IPs queried</span>
                </div>
            )}

            {/* Main layout: map + sidebar */}
            <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
                {/* Map */}
                <div style={{ flex: 1, position: 'relative' }}>
                    <div ref={mapContainerRef} style={{ width: '100%', height: '100%' }} />

                    {/* No data overlay */}
                    {!loading && data && points.length === 0 && (
                        <div style={{
                            position: 'absolute', inset: 0, background: 'rgba(247,247,247,0.92)',
                            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', zIndex: 999,
                        }}>
                            <div style={{ fontSize: 36, marginBottom: 10 }}>🌐</div>
                            <div style={{ fontSize: 14, color: 'var(--text-secondary)', fontWeight: 600, marginBottom: 6 }}>No geo data</div>
                            <div style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', maxWidth: 320 }}>{data.message || 'The query returned no results. Try a different time range or query type.'}</div>
                        </div>
                    )}
                    {!loading && !data && (
                        <div style={{
                            position: 'absolute', inset: 0, background: 'rgba(247,247,247,0.9)',
                            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', zIndex: 999,
                        }}>
                            <div style={{ fontSize: 40, marginBottom: 12 }}>🗺️</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--pwc-black)' }}>Sign-in GeoMap</div>
                            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>Select a query type and click <strong>Run Analysis</strong></div>
                        </div>
                    )}
                    {loading && (
                        <div style={{
                            position: 'absolute', inset: 0, background: 'rgba(247,247,247,0.85)',
                            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', zIndex: 999,
                        }}>
                            <div className="spinner spinner-lg" style={{ marginBottom: 12 }} />
                            <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Querying Sentinel + enriching IPs…</div>
                        </div>
                    )}

                    {/* Legend */}
                    {points.length > 0 && (
                        <div style={{
                            position: 'absolute', bottom: 20, right: 20, zIndex: 999,
                            background: '#fff', border: '1px solid var(--border)', borderRadius: 8,
                            padding: '12px 14px', boxShadow: '0 2px 12px rgba(0,0,0,.1)', minWidth: 160,
                        }}>
                            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--pwc-orange)', textTransform: 'uppercase', marginBottom: 8 }}>Activity Level</div>
                            {[
                                { color: '#C0392B', label: 'High (50%+ of max)' },
                                { color: '#E67E22', label: 'Medium (15–50%)' },
                                { color: '#27AE60', label: 'Low (<15%)' },
                            ].map(l => (
                                <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5, fontSize: 11 }}>
                                    <div style={{ width: 12, height: 12, borderRadius: '50%', background: l.color, flexShrink: 0 }} />
                                    {l.label}
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* IP list sidebar */}
                {points.length > 0 && (
                    <div style={{ width: 280, background: '#fff', borderLeft: '1px solid var(--border)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                        <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)' }}>
                            TOP IPS BY ACTIVITY
                        </div>
                        <div style={{ flex: 1, overflowY: 'auto', padding: '8px' }}>
                            {points.slice(0, 30).map(p => (
                                <div
                                    key={p.ip}
                                    onClick={() => {
                                        setSelectedIp(p);
                                        leafletMapRef.current?.setView([p.lat, p.lon], 8);
                                    }}
                                    style={{
                                        padding: '8px 10px', borderRadius: 6, marginBottom: 4, cursor: 'pointer',
                                        background: selectedIp?.ip === p.ip ? 'var(--pwc-orange-light)' : 'var(--pwc-pale-grey)',
                                        border: `1px solid ${selectedIp?.ip === p.ip ? 'var(--pwc-orange-border)' : 'transparent'}`,
                                        borderLeft: `3px solid ${p.threat_detected ? 'var(--critical)' : markerColor(p, data?.max_value || 1)}`,
                                        transition: 'all 0.1s',
                                    }}
                                >
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                                        <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600 }}>{p.ip}</span>
                                        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--pwc-orange)', flexShrink: 0 }}>{p.value}</span>
                                    </div>
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                                        📍 {[p.city, p.country].filter(Boolean).join(', ') || 'Unknown'}
                                    </div>
                                    <div style={{ display: 'flex', gap: 3, marginTop: 4, flexWrap: 'wrap' }}>
                                        {p.threat_detected && <span style={{ background: '#FCEAEA', color: '#C0392B', fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 10 }}>THREAT</span>}
                                        {p.is_vpn && <span style={{ background: '#F0F0F0', color: '#666', fontSize: 10, padding: '1px 6px', borderRadius: 10 }}>VPN</span>}
                                        {p.is_tor && <span style={{ background: '#FCEAEA', color: '#C0392B', fontSize: 10, padding: '1px 6px', borderRadius: 10 }}>TOR</span>}
                                        {(p.abuse_score || 0) > 50 && <span style={{ background: '#FEF3E8', color: '#E67E22', fontSize: 10, padding: '1px 6px', borderRadius: 10 }}>ABUSE {p.abuse_score}%</span>}
                                    </div>
                                </div>
                            ))}
                        </div>
                        {/* IP detail */}
                        {selectedIp && (
                            <div style={{ padding: 12, borderTop: '2px solid var(--pwc-orange)', background: 'var(--pwc-white)' }}>
                                <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>IP Details</div>
                                {[
                                    ['IP', selectedIp.ip],
                                    ['Location', [selectedIp.city, selectedIp.region, selectedIp.country].filter(Boolean).join(', ')],
                                    ['Organization', selectedIp.org],
                                    ['Activity', `${selectedIp.value} attempts`],
                                    ['Abuse Score', selectedIp.abuse_score != null ? `${selectedIp.abuse_score}%` : null],
                                    ['VPN', selectedIp.is_vpn ? 'Yes' : 'No'],
                                    ['Tor Exit', selectedIp.is_tor ? 'Yes' : 'No'],
                                    ['Threat', selectedIp.threat_description || (selectedIp.threat_detected ? 'Detected' : 'None')],
                                ].filter(([, v]) => v != null && v !== '').map(([k, v]) => (
                                    <div key={k as string} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4, gap: 8 }}>
                                        <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>{k}</span>
                                        <span style={{ fontFamily: k === 'IP' ? 'monospace' : undefined, fontWeight: 500, textAlign: 'right', wordBreak: 'break-all' }}>{v as string}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
