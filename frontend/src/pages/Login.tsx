import React, { useState, useEffect } from 'react';
import { storage } from '../utils/storage';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faLock, faUser, faShieldHalved, faFingerprint,
    faCrosshairs, faChartLine, faRobot, faGlobe, faUserShield,
    faBolt, faHeartPulse, faEye, faEyeSlash, faTriangleExclamation,
} from '@fortawesome/free-solid-svg-icons';

interface LoginProps { onLogin: () => void; }

const THREAT_FEED = [
    { type: 'Brute Force',  src: '203.0.113.45',  time: '47s', sev: 'H' },
    { type: 'APT-29 TTP',   src: '198.51.100.12', time: '2m',  sev: 'C' },
    { type: 'Lateral Move', src: '10.0.2.78',     time: '3m',  sev: 'H' },
    { type: 'Data Exfil',   src: '192.0.2.201',   time: '5m',  sev: 'C' },
    { type: 'Phishing Hit', src: '10.10.5.14',    time: '7m',  sev: 'M' },
    { type: 'Port Scan',    src: '172.16.0.33',   time: '9m',  sev: 'L' },
    { type: 'Cred Harvest', src: '203.0.113.99',  time: '11m', sev: 'H' },
];

const FEATURES = [
    { icon: faRobot,        label: 'ARIA AI',         desc: 'Natural language queries' },
    { icon: faCrosshairs,   label: 'Threat Hunting',  desc: '18 automated hunts' },
    { icon: faShieldHalved, label: 'MITRE ATT&CK',    desc: 'Full tactics coverage' },
    { icon: faChartLine,    label: 'Analytics',       desc: 'Real-time intelligence' },
    { icon: faGlobe,        label: 'IP Enrichment',   desc: 'Multi-source TI' },
    { icon: faUserShield,   label: 'Entity Exposure', desc: 'Identity risk profiling' },
    { icon: faBolt,         label: 'KQL Explorer',    desc: 'AI-generated queries' },
    { icon: faHeartPulse,   label: 'Platform Health', desc: 'Workspace monitoring' },
];

function sevColor(s: string) {
    if (s === 'C') return '#FF4444';
    if (s === 'H') return '#D04A02';
    if (s === 'M') return '#F59E0B';
    return '#3B82F6';
}
function sevLabel(s: string) {
    if (s === 'C') return 'CRIT';
    if (s === 'H') return 'HIGH';
    if (s === 'M') return 'MED';
    return 'LOW';
}

export default function Login({ onLogin }: LoginProps) {
    const [username, setUsername]         = useState('');
    const [password, setPassword]         = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError]               = useState('');
    const [loading, setLoading]           = useState(false);
    const [focused, setFocused]           = useState<'user' | 'pass' | null>(null);
    const [tilt, setTilt]                 = useState({ x: 0, y: 0 });
    const [feedIdx, setFeedIdx]           = useState(0);

    // ── 3-D card tilt ──
    useEffect(() => {
        const mv = (e: MouseEvent) => setTilt({
            x:  (e.clientX / window.innerWidth  - 0.5) * 5,
            y:  (e.clientY / window.innerHeight - 0.5) * 3.5,
        });
        window.addEventListener('mousemove', mv);
        return () => window.removeEventListener('mousemove', mv);
    }, []);

    // ── Threat feed ticker ──
    useEffect(() => {
        const t = setInterval(() => setFeedIdx(i => (i + 1) % THREAT_FEED.length), 3200);
        return () => clearInterval(t);
    }, []);

    const handleSubmit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setTimeout(() => {
            if (username === 'admin' && password === 'PwC@y14') {
                storage.setAuthenticated(true);
                onLogin();
            } else {
                setError('Authentication failed. Invalid credentials.');
                setLoading(false);
            }
        }, 900);
    };

    const inputStyle = (which: 'user' | 'pass'): React.CSSProperties => ({
        width: '100%',
        boxSizing: 'border-box',
        padding: '13px 16px 13px 44px',
        paddingRight: which === 'pass' ? 46 : 16,
        borderRadius: 10,
        border: `1.5px solid ${focused === which ? '#D04A02' : '#E4EAF2'}`,
        background: focused === which ? '#FFF8F5' : '#F8FAFC',
        color: '#0F1A25',
        fontSize: 13.5,
        outline: 'none',
        transition: 'all 0.22s',
        boxShadow: focused === which ? '0 0 0 3px rgba(208,74,2,0.1)' : '0 1px 3px rgba(0,0,0,0.05)',
        fontFamily: "'Plus Jakarta Sans', system-ui, sans-serif",
        letterSpacing: '0.01em',
    });

    const canSubmit = !loading && !!username && !!password;
    const feed = THREAT_FEED[feedIdx];

    return (
        <div style={{
            height: '100vh',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'linear-gradient(145deg, #FFF6EE 0%, #FFE8D2 30%, #FFD8B8 62%, #FFCBA0 100%)',
            overflow: 'hidden', position: 'relative',
            fontFamily: "'Plus Jakarta Sans', system-ui, sans-serif",
        }}>
            {/* Parallax dot grid */}
            <div style={{
                position: 'absolute', inset: '-50%', pointerEvents: 'none', zIndex: 0,
                backgroundImage: 'radial-gradient(rgba(180,70,0,0.09) 1.5px, transparent 1.5px)',
                backgroundSize: '38px 38px',
                transform: `translate(${tilt.x * 0.35}px, ${tilt.y * 0.35}px)`,
                transition: 'transform 0.18s ease-out',
            }} />

            {/* Ambient glow — top right warm burst */}
            <div style={{
                position: 'absolute', top: '-18%', right: '-12%', pointerEvents: 'none', zIndex: 1,
                width: '55vw', height: '55vw', borderRadius: '50%',
                background: 'radial-gradient(ellipse, rgba(208,74,2,0.13) 0%, transparent 62%)',
                filter: 'blur(70px)',
                animation: 'floatA 20s ease-in-out infinite alternate',
            }} />

            {/* Ambient glow — bottom left peach */}
            <div style={{
                position: 'absolute', bottom: '-20%', left: '-14%', pointerEvents: 'none', zIndex: 1,
                width: '50vw', height: '50vw', borderRadius: '50%',
                background: 'radial-gradient(ellipse, rgba(255,160,80,0.14) 0%, transparent 62%)',
                filter: 'blur(80px)',
                animation: 'floatB 26s ease-in-out infinite alternate',
            }} />

            {/* Soft centre highlight */}
            <div style={{
                position: 'absolute', top: '10%', left: '20%', pointerEvents: 'none', zIndex: 1,
                width: '60vw', height: '60vw', borderRadius: '50%',
                background: 'radial-gradient(ellipse, rgba(255,255,255,0.45) 0%, transparent 65%)',
                filter: 'blur(60px)',
            }} />

            {/* Perspective wrapper */}
            <div style={{ perspective: 1200, zIndex: 10, position: 'relative', width: 1060, maxWidth: '96vw' }}>
                <div style={{
                    display: 'flex',
                    minHeight: 640,
                    borderRadius: 20,
                    overflow: 'hidden',
                    transform: `rotateY(${tilt.x}deg) rotateX(${-tilt.y}deg)`,
                    transition: 'transform 0.18s ease-out',
                    boxShadow: '0 0 0 1px rgba(255,255,255,0.75), 0 28px 80px rgba(180,70,10,0.18), 0 8px 32px rgba(180,70,10,0.1)',
                    animation: 'cardIn 0.9s cubic-bezier(0.16,1,0.3,1)',
                }}>

                    {/* ══ LEFT — warm orange fill ══ */}
                    <div style={{
                        flex: '0 0 53%',
                        background: 'linear-gradient(148deg, #FFECD6 0%, #FFD8A8 42%, #FFC472 78%, #FFB85A 100%)',
                        display: 'flex', flexDirection: 'column',
                        padding: '36px 38px',
                        position: 'relative', overflow: 'hidden',
                        borderRight: '1px solid rgba(160,60,0,0.18)',
                    }}>
                        {/* Diagonal stripe texture */}
                        <div style={{
                            position: 'absolute', inset: 0, pointerEvents: 'none',
                            backgroundImage: 'repeating-linear-gradient(55deg, rgba(255,255,255,0.1) 0px, rgba(255,255,255,0.1) 1px, transparent 1px, transparent 22px)',
                        }} />
                        {/* Dot grid texture */}
                        <div style={{
                            position: 'absolute', inset: 0, pointerEvents: 'none',
                            backgroundImage: 'radial-gradient(rgba(140,50,0,0.09) 1.5px, transparent 1.5px)',
                            backgroundSize: '20px 20px',
                        }} />
                        {/* White highlight glow — top right */}
                        <div style={{
                            position: 'absolute', top: -80, right: -80,
                            width: 320, height: 320, borderRadius: '50%',
                            background: 'radial-gradient(circle, rgba(255,255,255,0.38) 0%, transparent 65%)',
                            pointerEvents: 'none',
                        }} />
                        {/* Deep amber glow — bottom left */}
                        <div style={{
                            position: 'absolute', bottom: -60, left: -60,
                            width: 260, height: 260, borderRadius: '50%',
                            background: 'radial-gradient(circle, rgba(180,60,0,0.14) 0%, transparent 65%)',
                            pointerEvents: 'none',
                        }} />
                        {/* Right-edge accent stripe */}
                        <div style={{
                            position: 'absolute', top: 0, right: 0, bottom: 0, width: 3,
                            background: 'linear-gradient(to bottom, transparent, rgba(140,50,0,0.35) 30%, rgba(180,70,0,0.35) 70%, transparent)',
                            pointerEvents: 'none',
                        }} />

                        {/* Logo row */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 28, position: 'relative', zIndex: 1 }}>
                            <div style={{ width: 36, height: 36, borderRadius: 8, background: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 3px 12px rgba(140,50,0,0.22)' }}>
                                <img src="/pwc-logo.jpg" alt="PwC" style={{ width: '80%', height: 'auto' }} />
                            </div>
                            <div style={{ width: 1, height: 20, background: 'rgba(130,50,0,0.22)' }} />
                            <div style={{ width: 36, height: 36, borderRadius: 8, background: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 3px 12px rgba(140,50,0,0.22)' }}>
                                <img src="/ms-sentinel-logo.png" alt="Sentinel" style={{ width: '80%', height: 'auto' }} />
                            </div>
                            <div style={{ fontSize: 8.5, fontWeight: 700, color: 'rgba(100,35,0,0.55)', textTransform: 'uppercase', letterSpacing: '0.16em', marginLeft: 5 }}>
                                PwC Sentinel Engineering
                            </div>
                        </div>

                        {/* Reticle + brand side-by-side */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 22, marginBottom: 8, position: 'relative', zIndex: 1 }}>

                            {/* Targeting reticle */}
                            <div style={{ position: 'relative', width: 90, height: 90, flexShrink: 0 }}>
                                <div style={{ position: 'absolute', inset: 0, borderRadius: '50%', border: '1px dashed rgba(120,40,0,0.38)', animation: 'rotCCW 22s linear infinite' }} />
                                <div style={{ position: 'absolute', inset: 11, borderRadius: '50%', border: '1.5px dashed rgba(140,50,0,0.55)', animation: 'rotCW 14s linear infinite' }} />
                                <div style={{ position: 'absolute', inset: 23, borderRadius: '50%', border: '1px solid rgba(130,45,0,0.3)' }} />
                                <div style={{ position: 'absolute', top: 0,    left: '50%', width: 1.5, height: 7, background: 'rgba(130,45,0,0.65)', transform: 'translateX(-50%)' }} />
                                <div style={{ position: 'absolute', bottom: 0, left: '50%', width: 1.5, height: 7, background: 'rgba(130,45,0,0.65)', transform: 'translateX(-50%)' }} />
                                <div style={{ position: 'absolute', left: 0,   top: '50%',  width: 7, height: 1.5, background: 'rgba(130,45,0,0.65)', transform: 'translateY(-50%)' }} />
                                <div style={{ position: 'absolute', right: 0,  top: '50%',  width: 7, height: 1.5, background: 'rgba(130,45,0,0.65)', transform: 'translateY(-50%)' }} />
                                <div style={{ position: 'absolute', top: '50%', left: 8, right: 8, height: 1, background: 'linear-gradient(90deg, rgba(130,45,0,0.12), rgba(130,45,0,0.38) 50%, rgba(130,45,0,0.12))', transform: 'translateY(-0.5px)' }} />
                                <div style={{ position: 'absolute', left: '50%', top: 8, bottom: 8, width: 1, background: 'linear-gradient(to bottom, rgba(130,45,0,0.12), rgba(130,45,0,0.38) 50%, rgba(130,45,0,0.12))', transform: 'translateX(-0.5px)' }} />
                                <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)' }}>
                                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#A03400', boxShadow: '0 0 10px rgba(160,52,0,0.7)', animation: 'dotPulse 2s ease-in-out infinite' }} />
                                </div>
                            </div>

                            {/* Brand text */}
                            <div style={{ minWidth: 0 }}>
                                <div style={{ fontSize: 8, fontWeight: 700, color: 'rgba(90,28,0,0.68)', textTransform: 'uppercase', letterSpacing: '0.22em', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
                                    <span style={{ display: 'inline-block', width: 14, height: 1, background: 'rgba(100,35,0,0.4)', flexShrink: 0 }} />
                                    Assessment &amp; Coverage Platform
                                </div>
                                <div style={{ fontSize: 46, fontWeight: 900, letterSpacing: '-0.03em', lineHeight: 1, color: '#3A1000', marginBottom: 3 }}>Sentinel</div>
                                <div className="vigil-grad" style={{ fontSize: 46, fontWeight: 900, letterSpacing: '-0.03em', lineHeight: 1 }}>Vigil</div>
                                <div style={{ fontSize: 10.5, color: 'rgba(90,28,0,0.45)', marginTop: 8, fontStyle: 'italic', letterSpacing: '0.04em' }}>
                                    Always Watching · Microsoft Sentinel
                                </div>
                            </div>
                        </div>

                        {/* Divider */}
                        <div style={{ height: 1, margin: '14px 0', background: 'rgba(120,45,0,0.15)', position: 'relative', zIndex: 1 }} />

                        {/* Feature grid */}
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '7px 10px', flex: 1, position: 'relative', zIndex: 1 }}>
                            {FEATURES.map(f => (
                                <div key={f.label} style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '8px 10px', borderRadius: 9, background: 'rgba(255,255,255,0.38)', border: '1px solid rgba(255,255,255,0.55)' }}>
                                    <div style={{ width: 26, height: 26, borderRadius: 6, flexShrink: 0, background: 'rgba(130,45,0,0.1)', border: '1px solid rgba(130,45,0,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                        <FontAwesomeIcon icon={f.icon} style={{ fontSize: 10, color: '#8B3000' }} />
                                    </div>
                                    <div>
                                        <div style={{ fontSize: 10.5, fontWeight: 600, color: '#3A1000', lineHeight: 1.3 }}>{f.label}</div>
                                        <div style={{ fontSize: 9.5, color: 'rgba(80,25,0,0.52)', lineHeight: 1.4 }}>{f.desc}</div>
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Live threat feed */}
                        <div style={{ marginTop: 14, position: 'relative', zIndex: 1 }}>
                            <div style={{ fontSize: 8, fontWeight: 700, color: 'rgba(90,28,0,0.5)', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 7, display: 'flex', alignItems: 'center', gap: 7 }}>
                                <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#16a34a', display: 'inline-block', boxShadow: '0 0 6px rgba(22,163,74,0.6)', animation: 'blink 1.4s ease-in-out infinite' }} />
                                Live Threat Feed
                            </div>
                            <div key={feedIdx} style={{ padding: '9px 12px', borderRadius: 9, background: 'rgba(255,255,255,0.42)', border: '1px solid rgba(255,255,255,0.58)', display: 'flex', alignItems: 'center', gap: 10, animation: 'feedSlide 0.45s ease' }}>
                                <span style={{ fontSize: 8, fontWeight: 800, padding: '2px 6px', borderRadius: 4, background: `${sevColor(feed.sev)}22`, color: sevColor(feed.sev), border: `1px solid ${sevColor(feed.sev)}55`, letterSpacing: '0.06em', flexShrink: 0 }}>
                                    {sevLabel(feed.sev)}
                                </span>
                                <span style={{ fontSize: 10.5, fontWeight: 600, color: '#3A1000', flex: 1 }}>{feed.type}</span>
                                <span style={{ fontSize: 9.5, color: 'rgba(90,28,0,0.5)', fontFamily: 'monospace' }}>{feed.src}</span>
                                <span style={{ fontSize: 9, color: 'rgba(90,28,0,0.38)', flexShrink: 0 }}>{feed.time} ago</span>
                            </div>
                        </div>

                        {/* Security badges */}
                        <div style={{ display: 'flex', gap: 6, marginTop: 10, flexWrap: 'wrap', position: 'relative', zIndex: 1 }}>
                            {['TLS 1.3', 'SOC Verified', 'Zero Trust'].map(b => (
                                <span key={b} style={{ fontSize: 8.5, fontWeight: 600, color: 'rgba(90,28,0,0.62)', border: '1px solid rgba(130,45,0,0.22)', borderRadius: 20, padding: '3px 9px', textTransform: 'uppercase', letterSpacing: '0.1em', background: 'rgba(255,255,255,0.32)', display: 'flex', alignItems: 'center', gap: 5 }}>
                                    <span style={{ width: 3.5, height: 3.5, borderRadius: '50%', background: '#A03400', display: 'inline-block', boxShadow: '0 0 4px rgba(160,52,0,0.5)' }} />
                                    {b}
                                </span>
                            ))}
                        </div>
                    </div>

                    {/* ══ RIGHT — clean white ══ */}
                    <div style={{ flex: '0 0 47%', background: 'rgba(253,253,255,0.97)', display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '52px 48px', position: 'relative' }}>
                        {/* Top orange bar */}
                        <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: 'linear-gradient(90deg, #D04A02, #FF9448 55%, transparent 100%)' }} />
                        {/* Corner tint */}
                        <div style={{ position: 'absolute', top: 0, right: 0, width: 260, height: 260, borderRadius: '50%', background: 'radial-gradient(circle, rgba(208,74,2,0.04) 0%, transparent 70%)', filter: 'blur(35px)', pointerEvents: 'none' }} />

                        {/* Shield icon */}
                        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 28 }}>
                            <div style={{ position: 'relative', width: 72, height: 72 }}>
                                <div style={{ position: 'absolute', inset: -10, borderRadius: '50%', border: '1px solid rgba(208,74,2,0.16)', animation: 'pulseRing 3.2s ease-out infinite' }} />
                                <div style={{ position: 'absolute', inset: -22, borderRadius: '50%', border: '1px solid rgba(208,74,2,0.06)', animation: 'pulseRing 3.2s ease-out infinite 1s' }} />
                                <div style={{ width: 72, height: 72, borderRadius: '50%', background: 'linear-gradient(145deg, #FFF5EE, #FFE6D0)', border: '1.5px solid rgba(208,74,2,0.18)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 6px 24px rgba(208,74,2,0.15)' }}>
                                    <FontAwesomeIcon icon={faShieldHalved} style={{ fontSize: 29, color: '#D04A02' }} />
                                </div>
                            </div>
                        </div>

                        {/* Heading */}
                        <div style={{ textAlign: 'center', marginBottom: 34 }}>
                            <div style={{ fontSize: 24, fontWeight: 800, color: '#0B1118', marginBottom: 7, letterSpacing: '-0.025em' }}>Secure Access</div>
                            <div style={{ fontSize: 11, color: '#96A6B8', letterSpacing: '0.15em', textTransform: 'uppercase', fontWeight: 500 }}>Authorized Personnel Only</div>
                        </div>

                        <form onSubmit={handleSubmit}>
                            {/* Username */}
                            <div style={{ marginBottom: 16 }}>
                                <label style={{ display: 'block', fontSize: 10, fontWeight: 700, color: '#7A8A9C', textTransform: 'uppercase', letterSpacing: '0.13em', marginBottom: 8 }}>Username</label>
                                <div style={{ position: 'relative' }}>
                                    <FontAwesomeIcon icon={faUser} style={{ position: 'absolute', left: 15, top: '50%', transform: 'translateY(-50%)', fontSize: 13, zIndex: 1, color: focused === 'user' ? '#D04A02' : '#BBC8D6', transition: 'color 0.22s' }} />
                                    <input type="text" placeholder="username" value={username} onChange={e => setUsername(e.target.value)} onFocus={() => setFocused('user')} onBlur={() => setFocused(null)} style={inputStyle('user')} />
                                </div>
                            </div>

                            {/* Password */}
                            <div style={{ marginBottom: 26 }}>
                                <label style={{ display: 'block', fontSize: 10, fontWeight: 700, color: '#7A8A9C', textTransform: 'uppercase', letterSpacing: '0.13em', marginBottom: 8 }}>Security Key</label>
                                <div style={{ position: 'relative' }}>
                                    <FontAwesomeIcon icon={faLock} style={{ position: 'absolute', left: 15, top: '50%', transform: 'translateY(-50%)', fontSize: 13, zIndex: 1, color: focused === 'pass' ? '#D04A02' : '#BBC8D6', transition: 'color 0.22s' }} />
                                    <input type={showPassword ? 'text' : 'password'} placeholder="••••••••••••" value={password} onChange={e => setPassword(e.target.value)} onFocus={() => setFocused('pass')} onBlur={() => setFocused(null)} style={inputStyle('pass')} />
                                    <button type="button" onClick={() => setShowPassword(p => !p)} tabIndex={-1} style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#BBC8D6', padding: 4, lineHeight: 1, transition: 'color 0.2s' }} onMouseEnter={e => (e.currentTarget.style.color = '#7A8A9C')} onMouseLeave={e => (e.currentTarget.style.color = '#BBC8D6')}>
                                        <FontAwesomeIcon icon={showPassword ? faEyeSlash : faEye} style={{ fontSize: 13 }} />
                                    </button>
                                </div>
                            </div>

                            {/* Error */}
                            {error && (
                                <div style={{ marginBottom: 18, padding: '11px 14px', borderRadius: 10, background: '#FFF5F0', border: '1.5px solid rgba(208,74,2,0.25)', color: '#B03600', fontSize: 12, animation: 'shake 0.4s ease', display: 'flex', alignItems: 'center', gap: 10 }}>
                                    <FontAwesomeIcon icon={faTriangleExclamation} style={{ fontSize: 13, flexShrink: 0, color: '#D04A02' }} />
                                    {error}
                                </div>
                            )}

                            {/* Submit */}
                            <button
                                type="submit"
                                disabled={!canSubmit}
                                style={{ width: '100%', height: 52, borderRadius: 11, border: 'none', background: canSubmit ? 'linear-gradient(135deg, #C04400 0%, #E8601A 50%, #FF7B35 100%)' : '#F0F4F8', color: canSubmit ? '#fff' : '#B0BEC5', fontWeight: 700, fontSize: 13, cursor: loading ? 'wait' : (canSubmit ? 'pointer' : 'not-allowed'), transition: 'all 0.25s', letterSpacing: '0.09em', textTransform: 'uppercase', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, boxShadow: canSubmit ? '0 8px 28px rgba(208,74,2,0.35), 0 2px 8px rgba(208,74,2,0.15)' : 'none', fontFamily: "'Plus Jakarta Sans', system-ui, sans-serif" }}
                                onMouseEnter={e => { if (canSubmit) { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 14px 36px rgba(208,74,2,0.42), 0 4px 12px rgba(208,74,2,0.2)'; } }}
                                onMouseLeave={e => { e.currentTarget.style.transform = ''; if (canSubmit) { e.currentTarget.style.boxShadow = '0 8px 28px rgba(208,74,2,0.35), 0 2px 8px rgba(208,74,2,0.15)'; } }}
                            >
                                {loading ? (
                                    <>
                                        <div style={{ width: 16, height: 16, border: '2px solid rgba(208,74,2,0.2)', borderTopColor: '#D04A02', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />
                                        <span style={{ color: '#D04A02', fontSize: 13 }}>Authenticating…</span>
                                    </>
                                ) : (
                                    <>
                                        <FontAwesomeIcon icon={faFingerprint} style={{ fontSize: 15 }} />
                                        Access Platform
                                    </>
                                )}
                            </button>
                        </form>

                        {/* Footer */}
                        <div style={{ marginTop: 30, paddingTop: 20, borderTop: '1px solid #EEF2F8', display: 'flex', justifyContent: 'center', gap: 22, fontSize: 10, color: '#B0BEC8', textTransform: 'uppercase', letterSpacing: '0.09em' }}>
                            {['TLS Encrypted', 'SOC Verified', 'v2.4.0'].map(t => (
                                <span key={t} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                    <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#D04A02', display: 'inline-block', boxShadow: '0 0 5px rgba(208,74,2,0.5)' }} />
                                    {t}
                                </span>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            <style>{`
                @keyframes spin       { to { transform: rotate(360deg); } }
                @keyframes cardIn     { from { opacity: 0; transform: translateY(32px) scale(0.96); } to { opacity: 1; transform: none; } }
                @keyframes pulseRing  { 0% { transform: scale(1); opacity: 0.5; } 100% { transform: scale(1.95); opacity: 0; } }
                @keyframes shake      { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-6px)} 75%{transform:translateX(6px)} }
                @keyframes rotCW      { to { transform: rotate(360deg); } }
                @keyframes rotCCW     { to { transform: rotate(-360deg); } }
                @keyframes dotPulse   { 0%,100% { box-shadow: 0 0 8px rgba(160,52,0,0.65); transform: scale(1); } 50% { box-shadow: 0 0 18px rgba(160,52,0,0.9); transform: scale(1.35); } }
                @keyframes blink      { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
                @keyframes feedSlide  { from { opacity: 0; transform: translateX(-8px); } to { opacity: 1; transform: translateX(0); } }
                @keyframes floatA     { 0% { transform: translate(0,0); } 100% { transform: translate(28px,16px); } }
                @keyframes floatB     { 0% { transform: translate(0,0); } 100% { transform: translate(-20px,24px); } }
                .vigil-grad {
                    background: linear-gradient(90deg, #7B1F00 0%, #C04000 100%);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                }
                input::placeholder { color: #BBC8D6; }
            `}</style>
        </div>
    );
}
