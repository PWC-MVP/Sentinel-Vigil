import { useState } from 'react';
import { useConfig } from '../hooks';
import { storage } from '../utils/storage';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faGear, faTriangleExclamation, faLock, faLightbulb, faShieldHalved,
    faKey, faLink, faBook, faSave, faRefresh,
    faCircleCheck, faUnlock, faRobot, faEye, faEyeSlash,
} from '@fortawesome/free-solid-svg-icons';

// ── Types ─────────────────────────────────────────────────────────────────────

interface AppConfig {
    // Sentinel / Azure
    SENTINEL_WORKSPACE_ID: string;
    AZURE_TENANT_ID: string;
    AZURE_CLIENT_ID: string;
    AZURE_CLIENT_SECRET: string;
    SUBSCRIPTION_ID: string;
    RESOURCE_GROUP: string;
    WORKSPACE_NAME: string;
    // Threat intel
    IPINFO_TOKEN: string;
    ABUSEIPDB_TOKEN: string;
    VPNAPI_TOKEN: string;
    VIRUSTOTAL_API_KEY: string;
    // LLM
    AZURE_ANTHROPIC_API_KEY: string;
    AZURE_ANTHROPIC_ENDPOINT: string;
    AZURE_ANTHROPIC_MODEL: string;
    // System
    SETTINGS_PASSWORD: string;
    OUTPUT_DIR: string;
}

const DEFAULTS: AppConfig = {
    SENTINEL_WORKSPACE_ID: '',
    AZURE_TENANT_ID: '',
    AZURE_CLIENT_ID: '',
    AZURE_CLIENT_SECRET: '',
    SUBSCRIPTION_ID: '',
    RESOURCE_GROUP: '',
    WORKSPACE_NAME: '',
    IPINFO_TOKEN: '',
    ABUSEIPDB_TOKEN: '',
    VPNAPI_TOKEN: '',
    VIRUSTOTAL_API_KEY: '',
    AZURE_ANTHROPIC_API_KEY: '',
    AZURE_ANTHROPIC_ENDPOINT: '',
    AZURE_ANTHROPIC_MODEL: 'claude-3-5-sonnet-20241022',
    SETTINGS_PASSWORD: '',
    OUTPUT_DIR: './reports',
};

function loadConfig(): AppConfig {
    const saved = storage.getEnvConfig();
    if (!saved) return { ...DEFAULTS };
    return { ...DEFAULTS, ...saved } as AppConfig;
}

// ── Shared field components ───────────────────────────────────────────────────

function FieldGroup({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <div style={{ marginBottom: 20 }}>
            <div style={{
                fontSize: 10, fontWeight: 700, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.1em',
                marginBottom: 12, paddingBottom: 6,
                borderBottom: '1px solid var(--border-subtle)',
            }}>
                {label}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {children}
            </div>
        </div>
    );
}

function Field({
    label, fieldKey, value, onChange, secret = false, placeholder = '',
}: {
    label: string;
    fieldKey: keyof AppConfig;
    value: string;
    onChange: (k: keyof AppConfig, v: string) => void;
    secret?: boolean;
    placeholder?: string;
}) {
    const [show, setShow] = useState(false);
    const type = secret && !show ? 'password' : 'text';

    return (
        <div>
            <label style={{
                fontSize: 11, color: 'var(--text-secondary)', fontWeight: 500,
                marginBottom: 4, display: 'block',
            }}>
                {label}
            </label>
            <div style={{ position: 'relative' }}>
                <input
                    type={type}
                    className="form-input"
                    style={{ width: '100%', fontSize: 12, fontFamily: 'monospace', paddingRight: secret ? 36 : undefined, boxSizing: 'border-box' }}
                    value={value}
                    placeholder={placeholder}
                    onChange={e => onChange(fieldKey, e.target.value)}
                />
                {secret && (
                    <button
                        type="button"
                        onClick={() => setShow(s => !s)}
                        style={{
                            position: 'absolute', right: 10, top: '50%',
                            transform: 'translateY(-50%)', background: 'none',
                            border: 'none', cursor: 'pointer',
                            color: 'var(--text-muted)', padding: 0, fontSize: 12,
                        }}
                        title={show ? 'Hide' : 'Show'}
                    >
                        <FontAwesomeIcon icon={show ? faEyeSlash : faEye} />
                    </button>
                )}
            </div>
        </div>
    );
}

function StatusBadge({ configured }: { configured: boolean }) {
    return (
        <span style={{
            display: 'inline-block', fontSize: 10, fontWeight: 700,
            padding: '2px 8px', borderRadius: 20,
            color: configured ? '#15803d' : 'var(--text-muted)',
            background: configured ? '#f0fdf4' : 'var(--bg-input)',
            border: `1px solid ${configured ? 'rgba(34,197,94,0.3)' : 'var(--border-subtle)'}`,
        }}>
            {configured ? '● Set' : '○ Empty'}
        </span>
    );
}

// ── Password gate ─────────────────────────────────────────────────────────────

function SettingsPasswordGate({ onUnlock }: { onUnlock: () => void }) {
    const [pin, setPin] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const verify = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (!pin) return;
        setLoading(true);
        setError('');
        try {
            const resp = await fetch('/api/auth/verify-settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pin }),
            });
            const data = await resp.json();
            if (data.valid) {
                storage.setSettingsUnlocked(true);
                onUnlock();
            } else {
                setError('Incorrect password. Access denied.');
                setPin('');
            }
        } catch {
            // If backend unreachable, allow unlock with localStorage password
            const saved = storage.getEnvConfig();
            const localPwd = saved?.SETTINGS_PASSWORD;
            if (localPwd && pin === localPwd) {
                storage.setSettingsUnlocked(true);
                onUnlock();
            } else {
                setError('Backend unreachable. Enter your locally saved settings password.');
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            height: 'calc(100vh - 160px)', padding: 40,
        }}>
            <div className="card" style={{ width: 380, padding: '44px 40px', textAlign: 'center' }}>
                <div style={{
                    width: 68, height: 68, borderRadius: '50%',
                    background: 'linear-gradient(135deg, #fff3ee, #ffe8dc)',
                    border: '1.5px solid rgba(208,74,2,0.25)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    margin: '0 auto 24px',
                    boxShadow: '0 4px 20px rgba(208,74,2,0.12)',
                }}>
                    <FontAwesomeIcon icon={faLock} style={{ fontSize: 26, color: '#D04A02' }} />
                </div>
                <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
                    Settings Protected
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 32 }}>
                    Enter the settings password to access configuration
                </div>
                <form onSubmit={verify}>
                    <input
                        type="password"
                        className="form-input"
                        placeholder="Settings password"
                        value={pin}
                        onChange={e => setPin(e.target.value)}
                        autoFocus
                        style={{
                            width: '100%', boxSizing: 'border-box',
                            marginBottom: 12, textAlign: 'center',
                            letterSpacing: '0.2em', fontSize: 15,
                        }}
                    />
                    {error && (
                        <div style={{
                            marginBottom: 14, padding: '9px 12px', borderRadius: 'var(--radius-sm)',
                            background: 'var(--risk-critical-bg)', border: '1px solid rgba(255,71,71,0.25)',
                            color: 'var(--critical)', fontSize: 12,
                            display: 'flex', alignItems: 'center', gap: 8,
                        }}>
                            <FontAwesomeIcon icon={faTriangleExclamation} style={{ flexShrink: 0 }} />
                            {error}
                        </div>
                    )}
                    <button
                        type="submit"
                        className="btn btn-primary"
                        disabled={loading || !pin}
                        style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
                    >
                        <FontAwesomeIcon
                            icon={loading ? faRefresh : faUnlock}
                            style={loading ? { animation: 'spin 0.8s linear infinite' } : {}}
                        />
                        {loading ? 'Verifying…' : 'Unlock Settings'}
                    </button>
                </form>
                <div style={{ marginTop: 20, fontSize: 11, color: 'var(--text-muted)' }}>
                    Default password is set via <code>SETTINGS_PASSWORD</code>
                </div>
            </div>
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
    );
}

// ── Main Settings page ────────────────────────────────────────────────────────

export default function Settings() {
    const [unlocked, setUnlocked] = useState(() => storage.isSettingsUnlocked());

    if (!unlocked) {
        return <SettingsPasswordGate onUnlock={() => setUnlocked(true)} />;
    }
    return <SettingsContent onLock={() => { storage.setSettingsUnlocked(false); setUnlocked(false); }} />;
}

// ── Settings content ──────────────────────────────────────────────────────────

function SettingsContent({ onLock }: { onLock: () => void }) {
    const { config } = useConfig();
    const [cfg, setCfg] = useState<AppConfig>(loadConfig);
    const [saving, setSaving] = useState(false);
    const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);

    const set = (key: keyof AppConfig, value: string) => {
        setCfg(prev => ({ ...prev, [key]: value }));
        setStatus(null);
    };

    const save = async () => {
        setSaving(true);
        setStatus(null);
        storage.setEnvConfig(cfg as unknown as Record<string, string>);

        try {
            const resp = await fetch('/api/config/env', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(cfg),
            });
            setStatus({
                ok: true,
                msg: resp.ok
                    ? 'Configuration saved to browser storage and synced to backend.'
                    : 'Saved to browser storage. Backend sync failed — will apply on next restart.',
            });
        } catch {
            setStatus({ ok: true, msg: 'Saved to browser storage. Backend unreachable — values persist locally.' });
        } finally {
            setSaving(false);
        }
    };

    const clearStorage = () => {
        if (!confirm('Clear all saved configuration from browser storage?')) return;
        storage.setEnvConfig({});
        setCfg({ ...DEFAULTS });
        setStatus({ ok: true, msg: 'Browser storage cleared.' });
    };

    return (
        <div>
            {/* ── Header ── */}
            <div className="page-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                        <div className="page-title">
                            <FontAwesomeIcon icon={faGear} style={{ marginRight: 12, fontSize: '0.9em', color: 'var(--brand)' }} />
                            Settings
                        </div>
                        <div className="page-subtitle">Configure your Azure, Sentinel and API credentials</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                        <button
                            className="btn btn-secondary btn-sm"
                            onClick={clearStorage}
                            style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
                        >
                            <FontAwesomeIcon icon={faRefresh} />
                            Clear Storage
                        </button>
                        <button
                            className="btn btn-secondary btn-sm"
                            onClick={onLock}
                            style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
                        >
                            <FontAwesomeIcon icon={faLock} />
                            Lock
                        </button>
                    </div>
                </div>
            </div>

            <div className="page-content" style={{ maxWidth: 900 }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 300px', gap: 20, alignItems: 'start' }}>

                    {/* ── Left: config form ── */}
                    <div>
                        {/* Microsoft Sentinel */}
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" />
                                Microsoft Sentinel
                            </div>
                            <FieldGroup label="Workspace">
                                <Field label="Workspace ID" fieldKey="SENTINEL_WORKSPACE_ID" value={cfg.SENTINEL_WORKSPACE_ID} onChange={set}
                                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
                                <Field label="Workspace Name" fieldKey="WORKSPACE_NAME" value={cfg.WORKSPACE_NAME} onChange={set}
                                    placeholder="My-Sentinel-Workspace" />
                                <Field label="Resource Group" fieldKey="RESOURCE_GROUP" value={cfg.RESOURCE_GROUP} onChange={set}
                                    placeholder="my-resource-group" />
                                <Field label="Subscription ID" fieldKey="SUBSCRIPTION_ID" value={cfg.SUBSCRIPTION_ID} onChange={set}
                                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
                            </FieldGroup>
                        </div>

                        {/* Azure Auth */}
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faLock} className="card-title-icon" />
                                Azure Authentication
                            </div>
                            <FieldGroup label="Service Principal">
                                <Field label="Tenant ID" fieldKey="AZURE_TENANT_ID" value={cfg.AZURE_TENANT_ID} onChange={set}
                                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
                                <Field label="Client ID" fieldKey="AZURE_CLIENT_ID" value={cfg.AZURE_CLIENT_ID} onChange={set}
                                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
                                <Field label="Client Secret" fieldKey="AZURE_CLIENT_SECRET" value={cfg.AZURE_CLIENT_SECRET} onChange={set}
                                    secret placeholder="your-client-secret" />
                            </FieldGroup>
                        </div>

                        {/* Threat Intelligence */}
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faKey} className="card-title-icon" />
                                Threat Intelligence API Tokens
                            </div>
                            <FieldGroup label="IP Reputation Services">
                                <Field label="IPInfo Token" fieldKey="IPINFO_TOKEN" value={cfg.IPINFO_TOKEN} onChange={set}
                                    secret placeholder="ipinfo.io token" />
                                <Field label="AbuseIPDB Token" fieldKey="ABUSEIPDB_TOKEN" value={cfg.ABUSEIPDB_TOKEN} onChange={set}
                                    secret placeholder="abuseipdb.com API key" />
                                <Field label="VPNAPI Token" fieldKey="VPNAPI_TOKEN" value={cfg.VPNAPI_TOKEN} onChange={set}
                                    secret placeholder="vpnapi.io token" />
                                <Field label="VirusTotal API Key" fieldKey="VIRUSTOTAL_API_KEY" value={cfg.VIRUSTOTAL_API_KEY} onChange={set}
                                    secret placeholder="virustotal.com API key" />
                            </FieldGroup>
                        </div>

                        {/* LLM / AI */}
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faRobot} className="card-title-icon" />
                                AI / LLM (ARIA)
                            </div>
                            <FieldGroup label="Azure Anthropic">
                                <Field label="API Key" fieldKey="AZURE_ANTHROPIC_API_KEY" value={cfg.AZURE_ANTHROPIC_API_KEY} onChange={set}
                                    secret placeholder="Azure Anthropic API key" />
                                <Field label="Endpoint" fieldKey="AZURE_ANTHROPIC_ENDPOINT" value={cfg.AZURE_ANTHROPIC_ENDPOINT} onChange={set}
                                    placeholder="https://your-resource.services.ai.azure.com" />
                                <Field label="Model" fieldKey="AZURE_ANTHROPIC_MODEL" value={cfg.AZURE_ANTHROPIC_MODEL} onChange={set}
                                    placeholder="claude-3-5-sonnet-20241022" />
                            </FieldGroup>
                        </div>

                        {/* System */}
                        <div className="card" style={{ marginBottom: 16 }}>
                            <div className="card-title">
                                <FontAwesomeIcon icon={faGear} className="card-title-icon" />
                                System
                            </div>
                            <FieldGroup label="Access &amp; Output">
                                <Field label="Settings Password" fieldKey="SETTINGS_PASSWORD" value={cfg.SETTINGS_PASSWORD} onChange={set}
                                    secret placeholder="admin" />
                                <Field label="Report Output Directory" fieldKey="OUTPUT_DIR" value={cfg.OUTPUT_DIR} onChange={set}
                                    placeholder="./reports" />
                            </FieldGroup>
                        </div>

                        {/* Save bar */}
                        {status && (
                            <div style={{
                                marginBottom: 12, padding: '10px 14px', borderRadius: 'var(--radius-sm)',
                                background: status.ok ? '#f0fdf4' : 'var(--risk-critical-bg)',
                                border: `1px solid ${status.ok ? 'rgba(34,197,94,0.3)' : 'rgba(255,71,71,0.3)'}`,
                                color: status.ok ? '#15803d' : 'var(--critical)',
                                fontSize: 12, display: 'flex', alignItems: 'center', gap: 8,
                            }}>
                                <FontAwesomeIcon icon={status.ok ? faCircleCheck : faTriangleExclamation} />
                                {status.msg}
                            </div>
                        )}

                        <button
                            className="btn btn-primary"
                            disabled={saving}
                            onClick={save}
                            style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: 8, height: 44, fontSize: 14 }}
                        >
                            <FontAwesomeIcon icon={faSave} />
                            {saving ? 'Saving…' : 'Save Configuration'}
                        </button>

                        <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
                            Values are stored in browser localStorage and synced to the backend <code>.env</code>
                        </div>
                    </div>

                    {/* ── Right: status sidebar ── */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

                        {/* Config completeness */}
                        <div className="card">
                            <div className="card-title">
                                <FontAwesomeIcon icon={faCircleCheck} className="card-title-icon" />
                                Configuration Status
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12 }}>
                                {([
                                    ['Workspace ID', 'SENTINEL_WORKSPACE_ID'],
                                    ['Tenant ID', 'AZURE_TENANT_ID'],
                                    ['Client ID', 'AZURE_CLIENT_ID'],
                                    ['Client Secret', 'AZURE_CLIENT_SECRET'],
                                    ['Subscription ID', 'SUBSCRIPTION_ID'],
                                    ['IPInfo', 'IPINFO_TOKEN'],
                                    ['AbuseIPDB', 'ABUSEIPDB_TOKEN'],
                                    ['Anthropic Key', 'AZURE_ANTHROPIC_API_KEY'],
                                ] as [string, keyof AppConfig][]).map(([label, key]) => (
                                    <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                        <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                                        <StatusBadge configured={!!cfg[key]} />
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Backend auth (live from API) */}
                        {config && (
                            <div className="card">
                                <div className="card-title">
                                    <FontAwesomeIcon icon={faLock} className="card-title-icon" />
                                    Azure Authentication
                                </div>
                                <div style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 10 }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                        <span style={{ color: 'var(--text-secondary)' }}>Status</span>
                                        <span style={{ color: config.auth.authenticated ? 'var(--low)' : 'var(--critical)', fontWeight: 600 }}>
                                            {config.auth.authenticated ? 'Authenticated' : 'Not authenticated'}
                                        </span>
                                    </div>
                                    {config.auth.method && (
                                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <span style={{ color: 'var(--text-secondary)' }}>Method</span>
                                            <span style={{ color: 'var(--text-primary)', fontSize: 12 }}>{config.auth.method}</span>
                                        </div>
                                    )}
                                    {config.auth.error && (
                                        <div style={{ padding: 10, background: 'var(--risk-critical-bg)', borderRadius: 'var(--radius-sm)', fontSize: 11, color: 'var(--high)', display: 'flex', gap: 8 }}>
                                            <FontAwesomeIcon icon={faTriangleExclamation} style={{ flexShrink: 0, marginTop: 1 }} />
                                            {config.auth.error}
                                        </div>
                                    )}
                                    {config.auth.hint && (
                                        <div style={{ padding: 10, background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', fontSize: 11, color: 'var(--text-secondary)', display: 'flex', gap: 8 }}>
                                            <FontAwesomeIcon icon={faLightbulb} style={{ color: 'var(--medium)', flexShrink: 0, marginTop: 1 }} />
                                            {config.auth.hint}
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Backend sentinel info */}
                        {config && (
                            <div className="card">
                                <div className="card-title">
                                    <FontAwesomeIcon icon={faShieldHalved} className="card-title-icon" />
                                    Microsoft Sentinel
                                </div>
                                <div style={{ fontSize: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
                                    {[
                                        ['Workspace', config.workspace_name],
                                        ['Resource Group', config.resource_group],
                                    ].map(([l, v]) => v ? (
                                        <div key={l} style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                                            <span style={{ color: 'var(--text-secondary)' }}>{l}</span>
                                            <span style={{ color: 'var(--text-primary)', textAlign: 'right' }}>{v}</span>
                                        </div>
                                    ) : null)}
                                    {config.sentinel_workspace_id && (
                                        <div>
                                            <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                                                Workspace ID
                                            </div>
                                            <div style={{ fontFamily: 'monospace', fontSize: 11, background: 'var(--bg-input)', padding: '6px 8px', borderRadius: 4, border: '1px solid var(--border-subtle)', wordBreak: 'break-all' }}>
                                                {config.sentinel_workspace_id}
                                            </div>
                                        </div>
                                    )}
                                    <div style={{ paddingTop: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                        <span style={{ color: 'var(--text-secondary)' }}>Config Status</span>
                                        <span style={{
                                            fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 20,
                                            color: config.config_valid ? '#15803d' : 'var(--critical)',
                                            background: config.config_valid ? '#f0fdf4' : 'var(--risk-critical-bg)',
                                            border: `1px solid ${config.config_valid ? 'rgba(34,197,94,0.3)' : 'rgba(255,71,71,0.3)'}`,
                                        }}>
                                            {config.config_valid ? '✓ Valid' : '✗ Incomplete'}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* API docs link */}
                        <div className="card">
                            <div className="card-title">
                                <FontAwesomeIcon icon={faLink} className="card-title-icon" />
                                Backend API
                            </div>
                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12 }}>
                                Interactive API documentation with all endpoints.
                            </div>
                            <a href="/api/docs" target="_blank" rel="noreferrer"
                                className="btn btn-secondary btn-sm"
                                style={{ display: 'flex', alignItems: 'center', gap: 8, width: 'fit-content' }}>
                                <FontAwesomeIcon icon={faBook} />
                                Open Swagger Docs
                            </a>
                            <div style={{ marginTop: 12, padding: 10, background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', fontSize: 11, color: 'var(--text-secondary)', display: 'flex', gap: 8 }}>
                                <FontAwesomeIcon icon={faLightbulb} style={{ color: 'var(--medium)', flexShrink: 0, marginTop: 1 }} />
                                <span>Start backend: <code>python -m backend.main</code></span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
