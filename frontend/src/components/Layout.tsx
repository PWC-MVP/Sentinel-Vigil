import React, { useState } from 'react';
import { useConfig } from '../hooks';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faRobot, faChartPie, faSearch, faFileLines, faGlobe, faBolt, faMapLocationDot,
    faShieldHalved, faChartLine, faGear, faBars, faXmark, faRightFromBracket,
    faHeartPulse, faWandMagicSparkles, faListCheck, faChartBar, faUserShield, faCrosshairs, faBookOpen,
    faCloudArrowUp, faCloudArrowDown, faClock, faDatabase,
} from '@fortawesome/free-solid-svg-icons';

interface LayoutProps {
    currentPage: string;
    onNavigate: (page: string) => void;
    onLogout: () => void;
    children: React.ReactNode;
}

const NAV = [
    { id: 'chat', label: 'ARIA Chat', icon: faRobot, section: 'AI ASSISTANT' },
    { id: 'dashboard', label: 'Dashboard', icon: faChartPie, section: 'MAIN' },
    { id: 'investigate', label: 'Investigate', icon: faSearch, section: 'MAIN' },
    { id: 'reports', label: 'Reports', icon: faFileLines, section: 'MAIN' },
    { id: 'enrich', label: 'IP Enrichment', icon: faGlobe, section: 'TOOLS' },
    { id: 'kql', label: 'KQL Explorer', icon: faBolt, section: 'TOOLS' },
    { id: 'geomap', label: 'Sign-in GeoMap', icon: faMapLocationDot, section: 'TOOLS' },
    { id: 'hunting', label: 'Threat Hunting', icon: faCrosshairs, section: 'TOOLS' },
    { id: 'mitre', label: 'MITRE Coverage', icon: faShieldHalved, section: 'ANALYTICS' },
    { id: 'analytics', label: 'Advanced Analytics', icon: faChartLine, section: 'ANALYTICS' },
    { id: 'incidents', label: 'Incident Analytics', icon: faChartBar, section: 'ANALYTICS' },
    { id: 'rules', label: 'Analytics Rules', icon: faListCheck, section: 'ANALYTICS' },
    { id: 'entities', label: 'Entity Exposure', icon: faUserShield, section: 'ANALYTICS' },
    { id: 'sentinel-health', label: 'Platform Health', icon: faHeartPulse, section: 'SENTINEL OPS' },
    { id: 'automation', label: 'Automation & SOAR', icon: faWandMagicSparkles, section: 'SENTINEL OPS' },
    { id: 'workbooks', label: 'Workbook Coverage', icon: faBookOpen, section: 'SENTINEL OPS' },
    { id: 'dcr', label: 'Ingestion Assessment', icon: faDatabase, section: 'SENTINEL OPS' },
    { id: 'backup', label: 'Backup Workspace', icon: faCloudArrowUp, section: 'SENTINEL OPS' },
    { id: 'restore', label: 'Restore', icon: faCloudArrowDown, section: 'SENTINEL OPS' },
    { id: 'snapshots', label: 'Snapshots', icon: faClock, section: 'SENTINEL OPS' },
    { id: 'settings', label: 'Settings', icon: faGear, section: 'SYSTEM' },
];
const SECTIONS = ['AI ASSISTANT', 'MAIN', 'TOOLS', 'ANALYTICS', 'SENTINEL OPS', 'SYSTEM'];

export default function Layout({ currentPage, onNavigate, onLogout, children }: LayoutProps) {
    const { config, loading } = useConfig();
    const [isCollapsed, setIsCollapsed] = useState(false);

    const authOk = config?.auth?.authenticated === true;
    const authStatus = loading ? 'loading' : !config ? 'err' : authOk ? 'ok' : 'err';
    const authLabel = loading
        ? 'Connecting…'
        : !config
            ? 'Backend offline'
            : authOk
                ? config.workspace_name || 'Connected'
                : `Auth failed: ${config.auth.error || 'Check credentials'}`;

    return (
        <div className="layout">
            {/* ── Top Bar ────────────────────────────────── */}
            <header className="topbar">
                <button
                    className="menu-toggle"
                    onClick={() => setIsCollapsed(!isCollapsed)}
                    title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
                >
                    <FontAwesomeIcon icon={isCollapsed ? faBars : faXmark} />
                </button>
                <img src="/pwc-logo.jpg" alt="PwC" className="topbar-logo" />
                <div className="topbar-divider" />
                <div>
                    <div className="topbar-title">Sentinel Vigil</div>
                    <div className="topbar-subtitle">Always Watching · Assessment & Coverage Platform</div>
                </div>
                <div className="topbar-right">
                    <div className="connection-badge">
                        <span className={`connection-dot ${authStatus}`} />
                        {authLabel}
                    </div>
                    <div className="topbar-divider" />
                    <button
                        className="btn btn-ghost btn-sm"
                        onClick={onLogout}
                        style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 8 }}
                    >
                        <FontAwesomeIcon icon={faRightFromBracket} />
                        Logout
                    </button>
                </div>
            </header>

            <div className="layout-body">
                {/* ── Sidebar ──────────────────────────────── */}
                <aside className={`sidebar ${isCollapsed ? 'collapsed' : ''}`}>
                    <nav className="sidebar-nav">
                        {SECTIONS.map(section => {
                            const items = NAV.filter(n => n.section === section);
                            return (
                                <React.Fragment key={section}>
                                    <div className="nav-section-label">{section}</div>
                                    {items.map(item => (
                                        <button
                                            key={item.id}
                                            className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
                                            onClick={() => onNavigate(item.id)}
                                            title={isCollapsed ? item.label : ''}
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
                </aside>

                {/* ── Main Content ─────────────────────────── */}
                <main className="main">
                    {children}
                </main>
            </div>

            {/* ── Footer ───────────────────────────────── */}
            <footer className="footer">
                <img src="/ms-sentinel-logo.png" alt="Microsoft Sentinel" className="footer-logo" />
                <div className="footer-divider" />
                <span>Created by Sentinel Engineering Team</span>
            </footer>
        </div>
    );
}
