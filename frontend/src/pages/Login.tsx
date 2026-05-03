import React, { useState, useEffect } from 'react';
import { storage } from '../utils/storage';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faLock, faUser, faShieldHalved, faFingerprint,
    faCrosshairs, faChartLine, faRobot, faGlobe, faUserShield,
    faBolt, faHeartPulse, faEye, faEyeSlash, faTriangleExclamation,
} from '@fortawesome/free-solid-svg-icons';

interface LoginProps {
    onLogin: () => void;
}

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

export default function Login({ onLogin }: LoginProps) {
    const [username, setUsername]         = useState('');
    const [password, setPassword]         = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError]               = useState('');
    const [loading, setLoading]           = useState(false);
    const [mousePos, setMousePos]         = useState({ x: 0, y: 0 });
    const [focused, setFocused]           = useState<'user' | 'pass' | null>(null);

    useEffect(() => {
        const move = (e: MouseEvent) => setMousePos({
            x: (e.clientX / window.innerWidth  - 0.5) * 22,
            y: (e.clientY / window.innerHeight - 0.5) * 22,
        });
        window.addEventListener('mousemove', move);
        return () => window.removeEventListener('mousemove', move);
    }, []);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setTimeout(() => {
            if (username === 'admin' && password === 'P@ssw0rd123!') {
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
        paddingRight: which === 'pass' ? 44 : 16,
        borderRadius: 10,
        border: `1.5px solid ${focused === which ? '#E07038' : '#e8ecf2'}`,
        background: focused === which ? '#fff7f3' : '#f7f9fc',
        color: '#1a2332',
        fontSize: 13,
        outline: 'none',
        transition: 'all 0.22s',
        boxShadow: focused === which
            ? '0 0 0 3px rgba(224,112,56,0.12)'
            : '0 1px 2px rgba(0,0,0,0.04)',
        fontFamily: "'Inter', system-ui, sans-serif",
    });

    const canSubmit = !loading && !!username && !!password;

    return (
        <div style={{
            height: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: '#eef1f7',
            overflow: 'hidden',
            position: 'relative',
            fontFamily: "'Inter', system-ui, sans-serif",
        }}>

            {/* ── Subtle dot grid with parallax ── */}
            <div style={{
                position: 'absolute',
                inset: '-50%',
                backgroundImage: 'radial-gradient(rgba(208,74,2,0.07) 1px, transparent 1px)',
                backgroundSize: '38px 38px',
                transform: `translate(${mousePos.x * 0.28}px, ${mousePos.y * 0.28}px)`,
                transition: 'transform 0.18s ease-out',
                pointerEvents: 'none',
            }} />

            {/* ── Soft warm glow top-right ── */}
            <div style={{
                position: 'absolute',
                top: '-15%', right: '-10%',
                width: '50vw', height: '50vw',
                borderRadius: '50%',
                background: 'radial-gradient(ellipse, rgba(255,140,80,0.1) 0%, transparent 65%)',
                filter: 'blur(60px)',
                pointerEvents: 'none',
                animation: 'floatA 20s ease-in-out infinite alternate',
            }} />

            {/* ── Soft cool glow bottom-left ── */}
            <div style={{
                position: 'absolute',
                bottom: '-15%', left: '-10%',
                width: '45vw', height: '45vw',
                borderRadius: '50%',
                background: 'radial-gradient(ellipse, rgba(180,200,240,0.12) 0%, transparent 65%)',
                filter: 'blur(70px)',
                pointerEvents: 'none',
                animation: 'floatB 26s ease-in-out infinite alternate',
            }} />

            {/* ── Main card ── */}
            <div style={{
                display: 'flex',
                width: 1000,
                maxWidth: '96vw',
                minHeight: 610,
                borderRadius: 22,
                overflow: 'hidden',
                boxShadow: '0 0 0 1px rgba(220,150,100,0.15), 0 20px 60px rgba(208,74,2,0.1), 0 8px 28px rgba(0,0,0,0.08)',
                animation: 'cardIn 0.75s cubic-bezier(0.16,1,0.3,1)',
                position: 'relative',
                zIndex: 10,
            }}>

                {/* ══ LEFT PANEL — light warm orange ══ */}
                <div style={{
                    flex: '0 0 52%',
                    background: 'linear-gradient(148deg, #FFD4A8 0%, #FFAA68 45%, #FF8C44 100%)',
                    display: 'flex',
                    flexDirection: 'column',
                    padding: '44px 42px',
                    position: 'relative',
                    overflow: 'hidden',
                }}>
                    {/* Soft dot texture */}
                    <div style={{
                        position: 'absolute', inset: 0,
                        backgroundImage: 'radial-gradient(rgba(255,255,255,0.25) 1px, transparent 1px)',
                        backgroundSize: '28px 28px',
                        pointerEvents: 'none',
                    }} />
                    {/* Warm inner glow top-right */}
                    <div style={{
                        position: 'absolute', top: -80, right: -80,
                        width: 300, height: 300, borderRadius: '50%',
                        background: 'radial-gradient(circle, rgba(255,255,255,0.22) 0%, transparent 68%)',
                        pointerEvents: 'none',
                    }} />
                    {/* Soft bottom fade */}
                    <div style={{
                        position: 'absolute', bottom: 0, left: 0, right: 0,
                        height: 100,
                        background: 'linear-gradient(to top, rgba(200,80,0,0.08), transparent)',
                        pointerEvents: 'none',
                    }} />

                    {/* Logos */}
                    <div style={{
                        display: 'flex', alignItems: 'center', gap: 12,
                        marginBottom: 44, position: 'relative', zIndex: 1,
                    }}>
                        <div style={{
                            width: 40, height: 40, borderRadius: 10,
                            background: '#fff',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            boxShadow: '0 4px 16px rgba(180,80,0,0.2)',
                        }}>
                            <img src="/pwc-logo.jpg" alt="PwC" style={{ width: '80%', height: 'auto' }} />
                        </div>
                        <div style={{ width: 1, height: 26, background: 'rgba(255,255,255,0.5)' }} />
                        <div style={{
                            width: 40, height: 40, borderRadius: 10,
                            background: '#fff',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            boxShadow: '0 4px 16px rgba(180,80,0,0.2)',
                        }}>
                            <img src="/ms-sentinel-logo.png" alt="Sentinel" style={{ width: '80%', height: 'auto' }} />
                        </div>
                        <div style={{
                            marginLeft: 4,
                            fontSize: 9, fontWeight: 700,
                            color: 'rgba(120,45,0,0.65)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.13em',
                        }}>
                            PwC Sentinel Engineering
                        </div>
                    </div>

                    {/* Brand */}
                    <div style={{ marginBottom: 8, position: 'relative', zIndex: 1 }}>
                        <div style={{
                            fontSize: 9, fontWeight: 700,
                            color: 'rgba(120,45,0,0.7)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.2em',
                            marginBottom: 14,
                            display: 'flex', alignItems: 'center', gap: 8,
                        }}>
                            <span style={{
                                display: 'inline-block', width: 16, height: 1,
                                background: 'rgba(120,45,0,0.4)',
                            }} />
                            Assessment &amp; Coverage Platform
                        </div>
                        <div style={{
                            fontSize: 52, fontWeight: 900,
                            letterSpacing: '-0.03em', lineHeight: 1,
                            color: 'rgba(255,255,255,0.65)',
                            marginBottom: 2,
                        }}>
                            Sentinel
                        </div>
                        <div style={{
                            fontSize: 52, fontWeight: 900,
                            letterSpacing: '-0.03em', lineHeight: 1,
                            color: '#7a2e00',
                        }}>
                            Vigil
                        </div>
                    </div>

                    <div style={{
                        fontSize: 12, color: 'rgba(120,45,0,0.55)',
                        marginBottom: 28, fontStyle: 'italic',
                        letterSpacing: '0.03em', position: 'relative', zIndex: 1,
                    }}>
                        Always Watching · Powered by Microsoft Sentinel
                    </div>

                    {/* Divider */}
                    <div style={{
                        height: 1, marginBottom: 22, position: 'relative', zIndex: 1,
                        background: 'rgba(180,80,0,0.2)',
                    }} />

                    {/* Feature grid */}
                    <div style={{
                        display: 'grid', gridTemplateColumns: '1fr 1fr',
                        gap: '10px 14px', flex: 1,
                        position: 'relative', zIndex: 1,
                    }}>
                        {FEATURES.map(f => (
                            <div key={f.label} style={{
                                display: 'flex', alignItems: 'center', gap: 10,
                                padding: '9px 11px', borderRadius: 10,
                                background: 'rgba(255,255,255,0.35)',
                                border: '1px solid rgba(255,255,255,0.5)',
                            }}>
                                <div style={{
                                    width: 28, height: 28, borderRadius: 7, flexShrink: 0,
                                    background: 'rgba(160,60,0,0.12)',
                                    border: '1px solid rgba(160,60,0,0.2)',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                }}>
                                    <FontAwesomeIcon icon={f.icon} style={{ fontSize: 11, color: '#7a2e00' }} />
                                </div>
                                <div>
                                    <div style={{
                                        fontSize: 11, fontWeight: 600,
                                        color: '#5a2000', lineHeight: 1.3,
                                    }}>
                                        {f.label}
                                    </div>
                                    <div style={{
                                        fontSize: 10, color: 'rgba(120,50,0,0.55)',
                                        lineHeight: 1.4, marginTop: 1,
                                    }}>
                                        {f.desc}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Security badges */}
                    <div style={{
                        display: 'flex', gap: 7, marginTop: 20,
                        flexWrap: 'wrap', position: 'relative', zIndex: 1,
                    }}>
                        {['TLS 1.3', 'SOC Verified', 'Zero Trust'].map(b => (
                            <span key={b} style={{
                                fontSize: 9, fontWeight: 600,
                                color: 'rgba(100,35,0,0.7)',
                                border: '1px solid rgba(180,80,0,0.25)',
                                borderRadius: 20, padding: '3px 10px',
                                textTransform: 'uppercase', letterSpacing: '0.09em',
                                background: 'rgba(255,255,255,0.4)',
                                display: 'flex', alignItems: 'center', gap: 6,
                            }}>
                                <span style={{
                                    width: 4, height: 4, borderRadius: '50%',
                                    background: '#b84000',
                                    display: 'inline-block',
                                }} />
                                {b}
                            </span>
                        ))}
                    </div>
                </div>

                {/* ══ RIGHT PANEL — pure white ══ */}
                <div style={{
                    flex: '0 0 48%',
                    background: '#ffffff',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'center',
                    padding: '52px 50px',
                    position: 'relative',
                }}>
                    {/* Very faint warm tint */}
                    <div style={{
                        position: 'absolute', top: 0, right: 0,
                        width: 240, height: 240, borderRadius: '50%',
                        background: 'radial-gradient(circle, rgba(255,160,80,0.05) 0%, transparent 70%)',
                        filter: 'blur(30px)',
                        pointerEvents: 'none',
                    }} />

                    {/* Shield icon */}
                    <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 26 }}>
                        <div style={{ position: 'relative', width: 70, height: 70 }}>
                            <div style={{
                                position: 'absolute', inset: -10, borderRadius: '50%',
                                border: '1px solid rgba(224,112,56,0.2)',
                                animation: 'pulseRing 3s ease-out infinite',
                            }} />
                            <div style={{
                                position: 'absolute', inset: -20, borderRadius: '50%',
                                border: '1px solid rgba(224,112,56,0.08)',
                                animation: 'pulseRing 3s ease-out infinite 0.8s',
                            }} />
                            <div style={{
                                width: 70, height: 70, borderRadius: '50%',
                                background: 'linear-gradient(135deg, #fff3e8, #ffe8d0)',
                                border: '1.5px solid rgba(224,112,56,0.25)',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                boxShadow: '0 4px 20px rgba(224,112,56,0.15)',
                            }}>
                                <FontAwesomeIcon icon={faShieldHalved} style={{ fontSize: 27, color: '#D04A02' }} />
                            </div>
                        </div>
                    </div>

                    {/* Heading */}
                    <div style={{ textAlign: 'center', marginBottom: 32 }}>
                        <div style={{
                            fontSize: 22, fontWeight: 800,
                            color: '#111827', marginBottom: 6,
                            letterSpacing: '-0.02em',
                        }}>
                            Secure Access
                        </div>
                        <div style={{
                            fontSize: 11, color: '#a0aec0',
                            letterSpacing: '0.12em',
                            textTransform: 'uppercase', fontWeight: 500,
                        }}>
                            Authorized Personnel Only
                        </div>
                    </div>

                    <form onSubmit={handleSubmit}>
                        {/* Username */}
                        <div style={{ marginBottom: 14 }}>
                            <label style={{
                                display: 'block', fontSize: 10, fontWeight: 700,
                                color: '#718096',
                                textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 8,
                            }}>
                                Username
                            </label>
                            <div style={{ position: 'relative' }}>
                                <FontAwesomeIcon icon={faUser} style={{
                                    position: 'absolute', left: 15, top: '50%',
                                    transform: 'translateY(-50%)', fontSize: 13, zIndex: 1,
                                    color: focused === 'user' ? '#E07038' : '#c8d0da',
                                    transition: 'color 0.22s',
                                }} />
                                <input
                                    type="text"
                                    placeholder="username"
                                    value={username}
                                    onChange={e => setUsername(e.target.value)}
                                    onFocus={() => setFocused('user')}
                                    onBlur={() => setFocused(null)}
                                    style={inputStyle('user')}
                                />
                            </div>
                        </div>

                        {/* Password */}
                        <div style={{ marginBottom: 24 }}>
                            <label style={{
                                display: 'block', fontSize: 10, fontWeight: 700,
                                color: '#718096',
                                textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 8,
                            }}>
                                Security Key
                            </label>
                            <div style={{ position: 'relative' }}>
                                <FontAwesomeIcon icon={faLock} style={{
                                    position: 'absolute', left: 15, top: '50%',
                                    transform: 'translateY(-50%)', fontSize: 13, zIndex: 1,
                                    color: focused === 'pass' ? '#E07038' : '#c8d0da',
                                    transition: 'color 0.22s',
                                }} />
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    placeholder="••••••••••••"
                                    value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    onFocus={() => setFocused('pass')}
                                    onBlur={() => setFocused(null)}
                                    style={inputStyle('pass')}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(p => !p)}
                                    tabIndex={-1}
                                    style={{
                                        position: 'absolute', right: 14, top: '50%',
                                        transform: 'translateY(-50%)',
                                        background: 'none', border: 'none', cursor: 'pointer',
                                        color: '#b8c4ce', padding: 4, lineHeight: 1,
                                        transition: 'color 0.2s',
                                    }}
                                    onMouseEnter={e => (e.currentTarget.style.color = '#718096')}
                                    onMouseLeave={e => (e.currentTarget.style.color = '#b8c4ce')}
                                >
                                    <FontAwesomeIcon icon={showPassword ? faEyeSlash : faEye} style={{ fontSize: 13 }} />
                                </button>
                            </div>
                        </div>

                        {/* Error */}
                        {error && (
                            <div style={{
                                marginBottom: 18, padding: '11px 14px', borderRadius: 10,
                                background: '#fff5f0',
                                border: '1.5px solid rgba(224,112,56,0.28)',
                                color: '#b83600', fontSize: 12,
                                animation: 'shake 0.4s ease',
                                display: 'flex', alignItems: 'center', gap: 10,
                            }}>
                                <FontAwesomeIcon icon={faTriangleExclamation} style={{ fontSize: 13, flexShrink: 0, color: '#E07038' }} />
                                {error}
                            </div>
                        )}

                        {/* Submit */}
                        <button
                            type="submit"
                            disabled={!canSubmit}
                            style={{
                                width: '100%', height: 50, borderRadius: 11, border: 'none',
                                background: canSubmit
                                    ? 'linear-gradient(135deg, #E86820 0%, #FF9448 100%)'
                                    : '#f0f4f8',
                                color: canSubmit ? '#fff' : '#b0bec5',
                                fontWeight: 700, fontSize: 13,
                                cursor: loading ? 'wait' : (canSubmit ? 'pointer' : 'not-allowed'),
                                transition: 'all 0.25s',
                                letterSpacing: '0.08em',
                                textTransform: 'uppercase',
                                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
                                boxShadow: canSubmit
                                    ? '0 8px 26px rgba(232,104,32,0.3), 0 2px 8px rgba(232,104,32,0.15)'
                                    : 'none',
                                fontFamily: "'Inter', system-ui, sans-serif",
                            }}
                            onMouseEnter={e => {
                                if (canSubmit) {
                                    e.currentTarget.style.transform = 'translateY(-1px)';
                                    e.currentTarget.style.boxShadow = '0 14px 34px rgba(232,104,32,0.38), 0 4px 12px rgba(232,104,32,0.2)';
                                }
                            }}
                            onMouseLeave={e => {
                                e.currentTarget.style.transform = '';
                                if (canSubmit) {
                                    e.currentTarget.style.boxShadow = '0 8px 26px rgba(232,104,32,0.3), 0 2px 8px rgba(232,104,32,0.15)';
                                }
                            }}
                        >
                            {loading ? (
                                <>
                                    <div style={{
                                        width: 16, height: 16,
                                        border: '2px solid rgba(232,104,32,0.25)',
                                        borderTopColor: '#E86820',
                                        borderRadius: '50%',
                                        animation: 'spin 0.7s linear infinite',
                                    }} />
                                    <span style={{ color: '#E86820', fontSize: 13 }}>Authenticating…</span>
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
                    <div style={{
                        marginTop: 28, paddingTop: 20,
                        borderTop: '1px solid #f0f4f8',
                        display: 'flex', justifyContent: 'center', gap: 20,
                        fontSize: 10, color: '#b0bec5',
                        textTransform: 'uppercase', letterSpacing: '0.08em',
                    }}>
                        {['TLS Encrypted', 'SOC Verified', 'v2.4.0'].map(t => (
                            <span key={t} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                <span style={{
                                    width: 5, height: 5, borderRadius: '50%',
                                    background: '#E07038',
                                    display: 'inline-block',
                                }} />
                                {t}
                            </span>
                        ))}
                    </div>
                </div>
            </div>

            <style>{`
                @keyframes spin      { to { transform: rotate(360deg); } }
                @keyframes cardIn    { from { opacity: 0; transform: translateY(30px) scale(0.97); } to { opacity: 1; transform: none; } }
                @keyframes pulseRing { 0% { transform: scale(1); opacity: 0.5; } 100% { transform: scale(1.85); opacity: 0; } }
                @keyframes shake     { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-6px)} 75%{transform:translateX(6px)} }
                @keyframes floatA    { 0% { transform: translate(0,0); } 100% { transform: translate(26px,16px); } }
                @keyframes floatB    { 0% { transform: translate(0,0); } 100% { transform: translate(-18px,22px); } }
                input::placeholder { color: #c8d0da; }
            `}</style>
        </div>
    );
}
