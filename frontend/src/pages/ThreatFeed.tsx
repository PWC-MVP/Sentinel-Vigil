import { useState, useEffect } from 'react';
import { http as axios } from '../api/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faNewspaper, faBug, faSearch, faFilter, faRotate,
    faArrowUpRightFromSquare, faTriangleExclamation, faRss, faSpinner,
    faMagnifyingGlassChart,
} from '@fortawesome/free-solid-svg-icons';
import ThreatInvestigatePanel from '../components/ThreatInvestigatePanel';

interface Article {
    id: string;
    title: string;
    summary: string;
    link: string;
    source: string;
    published: string;
    tags: string[];
    category: string;
}

interface CVEItem {
    id: string;
    title: string;
    description: string;
    vendor: string;
    product: string;
    date_added: string;
    due_date: string;
    ransomware_use: string;
    source: string;
    severity: string;
    score?: number;
    link: string;
    nvd_link: string;
}

const CATEGORIES = [
    'All', 'Ransomware', 'Phishing', 'Vulnerability', 'Data Breach',
    'APT', 'Malware', 'Supply Chain', 'DDoS', 'Cloud', 'AI Security', 'General',
];

const CAT_COLORS: Record<string, string> = {
    Ransomware: '#E74C3C',
    Phishing: '#E67E22',
    Vulnerability: '#9B59B6',
    'Data Breach': '#E91E63',
    APT: '#C0392B',
    Malware: '#D35400',
    'Supply Chain': '#8E44AD',
    DDoS: '#2980B9',
    Cloud: '#3498DB',
    'AI Security': '#16A085',
    General: '#7F8C8D',
};

function sevBadgeClass(sev: string, score?: number): string {
    const s = sev?.toLowerCase();
    if (s === 'critical' || (score !== undefined && score >= 9.0)) return 'badge-critical';
    if (s === 'high' || (score !== undefined && score >= 7.0)) return 'badge-high';
    if (s === 'medium' || (score !== undefined && score >= 4.0)) return 'badge-medium';
    return 'badge-low';
}

function timeAgo(dateStr: string): string {
    if (!dateStr) return '';
    try {
        const d = new Date(dateStr);
        if (isNaN(d.getTime())) return dateStr.slice(0, 10);
        const diff = Date.now() - d.getTime();
        const hours = Math.floor(diff / 3_600_000);
        if (hours < 1) return 'Just now';
        if (hours < 24) return `${hours}h ago`;
        const days = Math.floor(hours / 24);
        if (days < 30) return `${days}d ago`;
        return d.toLocaleDateString();
    } catch {
        return dateStr.slice(0, 10);
    }
}

export default function ThreatFeed() {
    const [tab, setTab] = useState<'news' | 'cves'>('news');
    const [articles, setArticles] = useState<Article[]>([]);
    const [cves, setCves] = useState<CVEItem[]>([]);
    const [newsLoading, setNewsLoading] = useState(true);
    const [cveLoading, setCveLoading] = useState(false);
    const [newsError, setNewsError] = useState<string | null>(null);
    const [cveError, setCveError] = useState<string | null>(null);
    const [category, setCategory] = useState('All');
    const [source, setSource] = useState('All');
    const [search, setSearch] = useState('');
    const [refreshing, setRefreshing] = useState(false);
    const [investigating, setInvestigating] = useState<Article | null>(null);

    const fetchNews = async () => {
        setNewsLoading(true);
        setNewsError(null);
        try {
            const res = await axios.get('/api/threat-feed/news', { timeout: 30000 });
            setArticles(res.data.articles || []);
        } catch {
            setNewsError('Failed to load news feed. External sources may be temporarily unavailable.');
        } finally {
            setNewsLoading(false);
        }
    };

    const fetchCves = async () => {
        setCveLoading(true);
        setCveError(null);
        try {
            const res = await axios.get('/api/threat-feed/cves', { timeout: 30000 });
            setCves(res.data.cves || []);
        } catch {
            setCveError('Failed to load CVE data. CISA / NVD APIs may be temporarily unavailable.');
        } finally {
            setCveLoading(false);
        }
    };

    useEffect(() => { fetchNews(); }, []);

    useEffect(() => {
        if (tab === 'cves' && cves.length === 0) fetchCves();
    }, [tab]);

    const handleRefresh = async () => {
        setRefreshing(true);
        try {
            await axios.post('/api/threat-feed/refresh');
            if (tab === 'news') await fetchNews();
            else await fetchCves();
        } finally {
            setRefreshing(false);
        }
    };

    const filteredArticles = articles.filter(a =>
        (category === 'All' || a.category === category) &&
        (source === 'All' || a.source === source) &&
        (!search || a.title.toLowerCase().includes(search.toLowerCase()) ||
            a.summary.toLowerCase().includes(search.toLowerCase()))
    );

    const filteredCves = cves.filter(c =>
        !search ||
        c.id.toLowerCase().includes(search.toLowerCase()) ||
        c.title.toLowerCase().includes(search.toLowerCase()) ||
        c.description.toLowerCase().includes(search.toLowerCase()) ||
        c.vendor.toLowerCase().includes(search.toLowerCase()) ||
        c.product.toLowerCase().includes(search.toLowerCase())
    );

    return (
        <div>
            {investigating && (
                <ThreatInvestigatePanel
                    article={investigating}
                    onClose={() => setInvestigating(null)}
                />
            )}
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faNewspaper} style={{ marginRight: 12, color: 'var(--brand)' }} />
                            Vigil Threat Reporter
                        </div>
                        <div className="page-subtitle">
                            Live threat news, advisories &amp; critical CVEs from 22 global security sources — powered by ARIA
                        </div>
                    </div>
                    <button
                        className="btn btn-ghost"
                        onClick={handleRefresh}
                        disabled={refreshing}
                        style={{ display: 'flex', alignItems: 'center', gap: 8 }}
                    >
                        <FontAwesomeIcon icon={refreshing ? faSpinner : faRotate} spin={refreshing} />
                        {refreshing ? 'Refreshing…' : 'Refresh Feed'}
                    </button>
                </div>

                <div className="tabs" style={{ marginTop: 12, marginBottom: 0 }}>
                    <button className={`tab ${tab === 'news' ? 'active' : ''}`} onClick={() => setTab('news')}>
                        <FontAwesomeIcon icon={faRss} style={{ marginRight: 8 }} />
                        News &amp; Articles {articles.length > 0 && `(${articles.length})`}
                    </button>
                    <button className={`tab ${tab === 'cves' ? 'active' : ''}`} onClick={() => setTab('cves')}>
                        <FontAwesomeIcon icon={faBug} style={{ marginRight: 8 }} />
                        CVE Alerts {cves.length > 0 && `(${cves.length})`}
                    </button>
                </div>
            </div>

            <div className="page-content">
                {/* Search bar */}
                <div style={{ marginBottom: 16 }}>
                    <div style={{ position: 'relative', maxWidth: 480 }}>
                        <FontAwesomeIcon icon={faSearch} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 12 }} />
                        <input
                            value={search}
                            onChange={e => setSearch(e.target.value)}
                            placeholder={tab === 'news' ? 'Search articles, threats, topics…' : 'Search CVE ID, product, vendor…'}
                            className="form-input"
                            style={{ width: '100%', paddingLeft: 30, boxSizing: 'border-box' }}
                        />
                    </div>
                </div>

                {/* ── NEWS TAB ─────────────────────────────────────────── */}
                {tab === 'news' && (
                    <div>
                        {/* Category filter */}
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10, alignItems: 'center' }}>
                            <FontAwesomeIcon icon={faFilter} style={{ color: 'var(--text-muted)', fontSize: 11 }} />
                            {CATEGORIES.map(c => (
                                <button
                                    key={c}
                                    onClick={() => setCategory(c)}
                                    className={`chip ${category === c ? 'active' : ''}`}
                                >
                                    {c}
                                </button>
                            ))}
                        </div>

                        {/* Source filter */}
                        <div style={{ display: 'flex', gap: 8, marginBottom: 20, alignItems: 'center' }}>
                            <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', whiteSpace: 'nowrap' }}>Source</span>
                            <select
                                value={source}
                                onChange={e => setSource(e.target.value)}
                                className="form-select"
                                style={{ fontSize: 12, minWidth: 200 }}
                            >
                                <option value="All">All Sources (22)</option>
                                <optgroup label="── News &amp; Journalism">
                                    <option>The Hacker News</option>
                                    <option>BleepingComputer</option>
                                    <option>Dark Reading</option>
                                    <option>Krebs on Security</option>
                                    <option>Threatpost</option>
                                    <option>Schneier on Security</option>
                                </optgroup>
                                <optgroup label="── Government / Standards">
                                    <option>CISA Alerts</option>
                                    <option>US-CERT Activity</option>
                                    <option>NIST Cybersecurity</option>
                                </optgroup>
                                <optgroup label="── Vendor Research">
                                    <option>Microsoft Security</option>
                                    <option>Palo Alto Unit42</option>
                                    <option>CrowdStrike Blog</option>
                                    <option>Mandiant Blog</option>
                                    <option>Securelist (Kaspersky)</option>
                                    <option>ESET WeLiveSecurity</option>
                                    <option>Malwarebytes Blog</option>
                                    <option>Check Point Research</option>
                                    <option>SentinelOne Blog</option>
                                    <option>Rapid7 Blog</option>
                                    <option>Recorded Future Blog</option>
                                </optgroup>
                                <optgroup label="── Deep Research">
                                    <option>Google Project Zero</option>
                                    <option>SANS ISC</option>
                                </optgroup>
                            </select>
                        </div>

                        {newsLoading ? (
                            <div style={{ padding: 60, textAlign: 'center' }}>
                                <div className="spinner spinner-lg" style={{ margin: '0 auto 12px' }} />
                                <div className="text-muted">Fetching latest cyber threat news…</div>
                            </div>
                        ) : newsError ? (
                            <div className="card" style={{ textAlign: 'center', padding: 40 }}>
                                <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: 'var(--high)', fontSize: 32, marginBottom: 12 }} />
                                <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>{newsError}</div>
                            </div>
                        ) : filteredArticles.length === 0 ? (
                            <div className="empty-state"><div className="empty-state-text">No articles match the current filters</div></div>
                        ) : (
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 14 }}>
                                {filteredArticles.map(a => {
                                    const catColor = CAT_COLORS[a.category] || '#7F8C8D';
                                    return (
                                        <div key={a.id} className="card-elevated"
                                            style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: '16px 18px' }}>

                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                                                <span style={{ fontSize: 9, fontWeight: 800, color: catColor, background: `${catColor}18`, padding: '2px 8px', borderRadius: 10, whiteSpace: 'nowrap' }}>
                                                    {a.category}
                                                </span>
                                                <span className="text-muted" style={{ fontSize: 10, whiteSpace: 'nowrap' }}>{timeAgo(a.published)}</span>
                                            </div>

                                            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.45 }}>
                                                {a.title}
                                            </div>

                                            {a.summary && (
                                                <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.65, flex: 1 }}>
                                                    {a.summary.slice(0, 220)}{a.summary.length > 220 ? '…' : ''}
                                                </div>
                                            )}

                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 4, flexWrap: 'wrap', gap: 6 }}>
                                                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                                                    <span className="badge badge-pwc" style={{ fontSize: 10 }}>
                                                        {a.source}
                                                    </span>
                                                    {a.tags.slice(0, 2).map(t => (
                                                        <span key={t} className="badge badge-muted" style={{ fontSize: 9 }}>
                                                            {t}
                                                        </span>
                                                    ))}
                                                </div>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                                                    <button
                                                        className="btn btn-sm btn-primary"
                                                        onClick={() => setInvestigating(a)}
                                                        style={{ fontSize: 10, padding: '3px 10px', display: 'flex', alignItems: 'center', gap: 5 }}
                                                        title="Investigate this threat in your Sentinel workspace"
                                                    >
                                                        <FontAwesomeIcon icon={faMagnifyingGlassChart} />
                                                        Investigate
                                                    </button>
                                                    {a.link && (
                                                        <a href={a.link} target="_blank" rel="noopener noreferrer"
                                                            style={{ fontSize: 11, color: 'var(--brand)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}
                                                            onMouseEnter={e => (e.currentTarget.style.textDecoration = 'underline')}
                                                            onMouseLeave={e => (e.currentTarget.style.textDecoration = 'none')}>
                                                            Read more <FontAwesomeIcon icon={faArrowUpRightFromSquare} style={{ fontSize: 9 }} />
                                                        </a>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                )}

                {/* ── CVE TAB ──────────────────────────────────────────── */}
                {tab === 'cves' && (
                    <div>
                        {cveLoading ? (
                            <div style={{ padding: 60, textAlign: 'center' }}>
                                <div className="spinner spinner-lg" style={{ margin: '0 auto 12px' }} />
                                <div className="text-muted">Fetching CISA KEV and NVD critical CVEs…</div>
                            </div>
                        ) : cveError ? (
                            <div className="card" style={{ textAlign: 'center', padding: 40 }}>
                                <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: 'var(--high)', fontSize: 32, marginBottom: 12 }} />
                                <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>{cveError}</div>
                            </div>
                        ) : filteredCves.length === 0 ? (
                            <div className="empty-state"><div className="empty-state-text">No CVEs match the search</div></div>
                        ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                {/* CISA KEV banner */}
                                {cves.some(c => c.source === 'CISA KEV') && (
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px', background: '#1a0a0a', border: '1px solid #E74C3C40', borderLeft: '3px solid #E74C3C', borderRadius: 8, marginBottom: 4 }}>
                                        <FontAwesomeIcon icon={faTriangleExclamation} style={{ color: '#E74C3C', fontSize: 14 }} />
                                        <div>
                                            <span style={{ fontSize: 11, fontWeight: 800, color: '#E74C3C' }}>CISA Known Exploited Vulnerabilities</span>
                                            <span style={{ fontSize: 11, color: '#94a3b8', marginLeft: 8 }}>These CVEs are actively exploited in the wild — patch immediately.</span>
                                        </div>
                                    </div>
                                )}

                                {filteredCves.map(c => {
                                    const isCisa = c.source === 'CISA KEV';
                                    return (
                                        <div key={c.id} className="card-elevated"
                                            style={{ padding: '14px 18px', borderLeft: isCisa ? '3px solid #E74C3C' : undefined }}>

                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
                                                <div style={{ flex: 1, minWidth: 240 }}>
                                                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6, flexWrap: 'wrap' }}>
                                                        <code className="mono" style={{ fontSize: 13, fontWeight: 800, color: 'var(--brand)', background: 'var(--pwc-orange-light)', padding: '2px 8px', borderRadius: 6 }}>
                                                            {c.id}
                                                        </code>
                                                        <span className={`badge ${sevBadgeClass(c.severity, c.score)}`}>
                                                            {c.severity}{c.score ? ` (${c.score})` : ''}
                                                        </span>
                                                        {isCisa && (
                                                            <span className="badge badge-critical" style={{ fontSize: 9, letterSpacing: '0.04em' }}>
                                                                ACTIVELY EXPLOITED
                                                            </span>
                                                        )}
                                                        {c.ransomware_use === 'Known' && (
                                                            <span className="badge badge-high" style={{ fontSize: 9 }}>
                                                                RANSOMWARE
                                                            </span>
                                                        )}
                                                    </div>
                                                    {c.title && c.title !== c.id && (
                                                        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>{c.title}</div>
                                                    )}
                                                    {c.description && (
                                                        <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                                            {c.description.slice(0, 300)}{c.description.length > 300 ? '…' : ''}
                                                        </div>
                                                    )}
                                                </div>

                                                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-end', flexShrink: 0 }}>
                                                    {c.vendor && (
                                                        <div style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'right' }}>
                                                            <span style={{ fontWeight: 600 }}>{c.vendor}</span>
                                                            {c.product && <span> / {c.product}</span>}
                                                        </div>
                                                    )}
                                                    {c.date_added && (
                                                        <div className="text-muted" style={{ fontSize: 10 }}>Added: {c.date_added}</div>
                                                    )}
                                                    {c.due_date && (
                                                        <div style={{ fontSize: 10, color: '#E74C3C', fontWeight: 600 }}>Patch by: {c.due_date}</div>
                                                    )}
                                                    <a href={c.nvd_link || c.link} target="_blank" rel="noopener noreferrer"
                                                        style={{ fontSize: 11, color: 'var(--brand)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}
                                                        onMouseEnter={e => (e.currentTarget.style.textDecoration = 'underline')}
                                                        onMouseLeave={e => (e.currentTarget.style.textDecoration = 'none')}>
                                                        NVD Details <FontAwesomeIcon icon={faArrowUpRightFromSquare} style={{ fontSize: 9 }} />
                                                    </a>
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
