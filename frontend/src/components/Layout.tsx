import React, { useState, useEffect } from 'react';
import { useConfig } from '../hooks';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faRobot, faChartPie, faSearch, faFileLines, faGlobe, faBolt, faMapLocationDot,
    faShieldHalved, faChartLine, faGear, faRightFromBracket,
    faHeartPulse, faWandMagicSparkles, faListCheck, faChartBar, faUserShield, faCrosshairs, faBookOpen,
    faCloudArrowUp, faCloudArrowDown, faClock, faDatabase, faNewspaper,
    faPalette, faCheck, faAnglesLeft, faAnglesRight,
} from '@fortawesome/free-solid-svg-icons';

interface LayoutProps {
    currentPage: string;
    onNavigate: (page: string) => void;
    onLogout: () => void;
    children: React.ReactNode;
}

/* ── Accent colour themes ─────────────────────────────────────────────────── */
const THEMES = [
    {
        id: 'orange',
        name: 'PwC Orange',
        color: '#D04A02',
        hover: '#B53A00',
        light: '#FEF3EE',
        border: 'rgba(208,74,2,0.15)',
        glow: 'rgba(208,74,2,0.08)',
        gradient: 'linear-gradient(135deg,#D04A02 0%,#E55A12 100%)',
        gradientHover: 'linear-gradient(135deg,#B53A00 0%,#D04A02 100%)',
    },
    {
        id: 'blue',
        name: 'Royal Blue',
        color: '#2563EB',
        hover: '#1D4ED8',
        light: '#EFF6FF',
        border: 'rgba(37,99,235,0.15)',
        glow: 'rgba(37,99,235,0.08)',
        gradient: 'linear-gradient(135deg,#2563EB 0%,#3B82F6 100%)',
        gradientHover: 'linear-gradient(135deg,#1D4ED8 0%,#2563EB 100%)',
    },
    {
        id: 'emerald',
        name: 'Emerald',
        color: '#059669',
        hover: '#047857',
        light: '#ECFDF5',
        border: 'rgba(5,150,105,0.15)',
        glow: 'rgba(5,150,105,0.08)',
        gradient: 'linear-gradient(135deg,#059669 0%,#10B981 100%)',
        gradientHover: 'linear-gradient(135deg,#047857 0%,#059669 100%)',
    },
    {
        id: 'violet',
        name: 'Violet',
        color: '#7C3AED',
        hover: '#6D28D9',
        light: '#F5F3FF',
        border: 'rgba(124,58,237,0.15)',
        glow: 'rgba(124,58,237,0.08)',
        gradient: 'linear-gradient(135deg,#7C3AED 0%,#A855F7 100%)',
        gradientHover: 'linear-gradient(135deg,#6D28D9 0%,#7C3AED 100%)',
    },
    {
        id: 'rose',
        name: 'Rose',
        color: '#E11D48',
        hover: '#BE123C',
        light: '#FFF1F2',
        border: 'rgba(225,29,72,0.15)',
        glow: 'rgba(225,29,72,0.08)',
        gradient: 'linear-gradient(135deg,#E11D48 0%,#F43F5E 100%)',
        gradientHover: 'linear-gradient(135deg,#BE123C 0%,#E11D48 100%)',
    },
    {
        id: 'amber',
        name: 'Amber',
        color: '#D97706',
        hover: '#B45309',
        light: '#FFFBEB',
        border: 'rgba(217,119,6,0.15)',
        glow: 'rgba(217,119,6,0.08)',
        gradient: 'linear-gradient(135deg,#D97706 0%,#F59E0B 100%)',
        gradientHover: 'linear-gradient(135deg,#B45309 0%,#D97706 100%)',
    },
    {
        id: 'slate',
        name: 'Slate',
        color: '#334155',
        hover: '#1E293B',
        light: '#F1F5F9',
        border: 'rgba(51,65,85,0.15)',
        glow: 'rgba(51,65,85,0.08)',
        gradient: 'linear-gradient(135deg,#334155 0%,#475569 100%)',
        gradientHover: 'linear-gradient(135deg,#1E293B 0%,#334155 100%)',
    },
    {
        id: 'teal',
        name: 'Teal',
        color: '#0D9488',
        hover: '#0F766E',
        light: '#F0FDFA',
        border: 'rgba(13,148,136,0.15)',
        glow: 'rgba(13,148,136,0.08)',
        gradient: 'linear-gradient(135deg,#0D9488 0%,#14B8A6 100%)',
        gradientHover: 'linear-gradient(135deg,#0F766E 0%,#0D9488 100%)',
    },
] as const;

type ThemeId = typeof THEMES[number]['id'];

/* Apply a theme's accent tokens to :root CSS variables */
function applyTheme(id: ThemeId) {
    const t = THEMES.find(x => x.id === id) ?? THEMES[0];
    const root = document.documentElement;
    root.style.setProperty('--pwc-orange',        t.color);
    root.style.setProperty('--pwc-orange-hover',  t.hover);
    root.style.setProperty('--pwc-orange-light',  t.light);
    root.style.setProperty('--pwc-orange-border', t.border);
    root.style.setProperty('--pwc-orange-glow',   t.glow);
    root.style.setProperty('--gradient-orange',       t.gradient);
    root.style.setProperty('--gradient-orange-hover', t.gradientHover);
    root.style.setProperty('--accent',        t.color);
    root.style.setProperty('--accent-hover',  t.hover);
    root.style.setProperty('--accent-light',  t.light);
    root.style.setProperty('--accent-border', t.border);
    root.style.setProperty('--accent-glow',   t.glow);
    root.style.setProperty('--brand',         t.color);
    root.style.setProperty('--text-link',     t.color);
    // Brand shadow
    const r = parseInt(t.color.slice(1, 3), 16);
    const g = parseInt(t.color.slice(3, 5), 16);
    const b = parseInt(t.color.slice(5, 7), 16);
    root.style.setProperty('--shadow-brand',
        `0 4px 16px rgba(${r},${g},${b},0.22), 0 1px 3px rgba(${r},${g},${b},0.12)`);
}

/* ── Nav items ────────────────────────────────────────────────────────────── */
const NAV = [
    { id: 'chat',            label: 'ARIA Chat',             icon: faRobot,             section: 'AI ASSISTANT' },
    { id: 'dashboard',       label: 'Dashboard',             icon: faChartPie,          section: 'MAIN' },
    { id: 'investigate',     label: 'Investigate',           icon: faSearch,            section: 'MAIN' },
    { id: 'reports',         label: 'Reports',               icon: faFileLines,         section: 'MAIN' },
    { id: 'enrich',          label: 'IP Enrichment',         icon: faGlobe,             section: 'TOOLS' },
    { id: 'kql',             label: 'Log Parser',            icon: faBolt,              section: 'TOOLS' },
    { id: 'geomap',          label: 'Sign-in GeoMap',        icon: faMapLocationDot,    section: 'TOOLS' },
    { id: 'hunting',         label: 'Threat Hunting',        icon: faCrosshairs,        section: 'TOOLS' },
    { id: 'threat-feed',     label: 'Vigil Threat Reporter', icon: faNewspaper,         section: 'TOOLS' },
    { id: 'mitre',           label: 'MITRE Coverage',        icon: faShieldHalved,      section: 'ANALYTICS' },
    { id: 'analytics',       label: 'Advanced Analytics',    icon: faChartLine,         section: 'ANALYTICS' },
    { id: 'incidents',       label: 'Incident Analytics',    icon: faChartBar,          section: 'ANALYTICS' },
    { id: 'rules',           label: 'Analytics Rules',       icon: faListCheck,         section: 'ANALYTICS' },
    { id: 'entities',        label: 'Entity Exposure',       icon: faUserShield,        section: 'ANALYTICS' },
    { id: 'sentinel-health', label: 'Platform Health',       icon: faHeartPulse,        section: 'SENTINEL OPS' },
    { id: 'automation',      label: 'Automation & SOAR',     icon: faWandMagicSparkles, section: 'SENTINEL OPS' },
    { id: 'workbooks',       label: 'Workbook Coverage',     icon: faBookOpen,          section: 'SENTINEL OPS' },
    { id: 'dcr',             label: 'Ingestion Assessment',  icon: faDatabase,          section: 'SENTINEL OPS' },
    { id: 'backup',          label: 'Backup Workspace',      icon: faCloudArrowUp,      section: 'SENTINEL OPS' },
    { id: 'restore',         label: 'Restore',               icon: faCloudArrowDown,    section: 'SENTINEL OPS' },
    { id: 'snapshots',       label: 'Snapshots',             icon: faClock,             section: 'SENTINEL OPS' },
    { id: 'settings',        label: 'Settings',              icon: faGear,              section: 'SYSTEM' },
];

const SECTIONS = ['AI ASSISTANT', 'MAIN', 'TOOLS', 'ANALYTICS', 'SENTINEL OPS', 'SYSTEM'];

/* ── Component ────────────────────────────────────────────────────────────── */
export default function Layout({ currentPage, onNavigate, onLogout, children }: LayoutProps) {
    const { config, loading } = useConfig();

    const [accentId, setAccentId] = useState<ThemeId>(
        () => (localStorage.getItem('sv-accent') as ThemeId | null) ?? 'orange',
    );
    const [paletteOpen, setPaletteOpen] = useState(false);
    const [collapsed, setCollapsed] = useState(
        () => localStorage.getItem('sv-sidebar-collapsed') === 'true',
    );

    /* Apply theme on mount + whenever accent changes */
    useEffect(() => {
        applyTheme(accentId);
        localStorage.setItem('sv-accent', accentId);
    }, [accentId]);

    /* Persist sidebar collapsed state */
    useEffect(() => {
        localStorage.setItem('sv-sidebar-collapsed', String(collapsed));
    }, [collapsed]);

    const authOk = config?.auth?.authenticated === true;
    const authStatus = loading ? 'loading' : !config ? 'err' : authOk ? 'ok' : 'err';
    const workspaceName = loading
        ? 'Connecting…'
        : !config
            ? 'Backend offline'
            : authOk
                ? config.workspace_name || 'Connected'
                : `Auth failed: ${config.auth.error || 'Check credentials'}`;

    const activeTheme = THEMES.find(t => t.id === accentId) ?? THEMES[0];

    return (
        <div className="layout">

            {/* ── Top Bar ─────────────────────────────────────────────── */}
            <header className="topbar">
                <img src="/pwc-logo.jpg" alt="PwC" className="topbar-logo" />
                <div className="topbar-divider" />
                <div>
                    <div className="topbar-title">Sentinel Vigil</div>
                    <div className="topbar-subtitle">Always Watching · Assessment &amp; Coverage Platform</div>
                </div>

                <div className="topbar-right">
                    <div className="connection-badge">
                        <span className={`connection-dot ${authStatus}`} />
                        <span>{workspaceName}</span>
                    </div>
                    <div className="topbar-divider" />
                    <button
                        className="btn btn-ghost btn-sm"
                        onClick={onLogout}
                        style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                        <FontAwesomeIcon icon={faRightFromBracket} />
                        <span>Logout</span>
                    </button>
                </div>
            </header>

            <div className="layout-body">

                {/* ── Sidebar ─────────────────────────────────────────── */}
                <aside className={`sidebar${collapsed ? ' collapsed' : ''}`}>
                    {/* Collapse toggle */}
                    <div className="sidebar-toggle">
                        <button
                            className="sidebar-toggle-btn"
                            onClick={() => setCollapsed(c => !c)}
                            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                        >
                            <FontAwesomeIcon icon={collapsed ? faAnglesRight : faAnglesLeft} />
                        </button>
                    </div>
                    <nav className="sidebar-nav">
                        {SECTIONS.map((section, sectionIndex) => {
                            const items = NAV.filter(n => n.section === section);
                            return (
                                <React.Fragment key={section}>
                                    {sectionIndex > 0 && <div className="nav-section-divider" />}
                                    <div className="nav-section-label">{section}</div>
                                    {items.map(item => (
                                        <button
                                            key={item.id}
                                            className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
                                            onClick={() => onNavigate(item.id)}
                                            data-tooltip={item.label}
                                        >
                                            <span className="nav-item-icon">
                                                <FontAwesomeIcon icon={item.icon} fixedWidth />
                                            </span>
                                            <span className="nav-item-label">{item.label}</span>
                                        </button>
                                    ))}
                                </React.Fragment>
                            );
                        })}
                    </nav>

                    {/* ── Colour theme section ─────────────────────────── */}
                    <div className="sidebar-palette-wrap">
                        {/* Toggle button */}
                        <button
                            className="sidebar-palette-btn"
                            onClick={() => setPaletteOpen(o => !o)}
                            title="Change accent colour"
                        >
                            <span className="sidebar-palette-swatch" style={{ background: activeTheme.color }} />
                            <span className="sidebar-palette-label">Theme</span>
                            <span className="sidebar-palette-name">{activeTheme.name}</span>
                            <FontAwesomeIcon
                                icon={faPalette}
                                style={{ marginLeft: 'auto', fontSize: 11, opacity: 0.5 }}
                            />
                        </button>

                        {/* Swatches panel */}
                        {paletteOpen && (
                            <div className="sidebar-palette-panel">
                                {THEMES.map(t => (
                                    <button
                                        key={t.id}
                                        className="sidebar-palette-dot"
                                        title={t.name}
                                        onClick={() => { setAccentId(t.id); setPaletteOpen(false); }}
                                        style={{
                                            background: t.gradient,
                                            boxShadow: accentId === t.id
                                                ? `0 0 0 2px #fff, 0 0 0 4px ${t.color}`
                                                : `0 2px 6px rgba(0,0,0,0.18)`,
                                        }}
                                    >
                                        {accentId === t.id && (
                                            <FontAwesomeIcon icon={faCheck} style={{ fontSize: 9, color: '#fff' }} />
                                        )}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Version stamp */}
                    <div className="sidebar-version">v2.4.0</div>
                </aside>

                {/* ── Main Content ─────────────────────────────────────── */}
                <main className="main">
                    {children}
                </main>
            </div>
        </div>
    );
}
