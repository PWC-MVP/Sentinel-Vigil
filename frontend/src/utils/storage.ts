import type { Config } from '../api/client';

const KEYS = {
    IS_AUTHENTICATED:   'sv_auth',
    SETTINGS_UNLOCKED:  'sv_settings_unlocked',
    ENV_CONFIG:         'sv_env_config',
    PUBLIC_CONFIG:      'sv_public_config',
} as const;

export type EnvConfig = Record<string, string>;

function safeGet<T>(key: string): T | null {
    try {
        const raw = localStorage.getItem(key);
        return raw ? (JSON.parse(raw) as T) : null;
    } catch {
        return null;
    }
}

function safeSet(key: string, value: unknown): void {
    try {
        localStorage.setItem(key, JSON.stringify(value));
    } catch (e) {
        console.warn('localStorage write failed:', e);
    }
}

export const storage = {
    // ── Auth ────────────────────────────────────────────────────────────────
    isAuthenticated: (): boolean =>
        localStorage.getItem(KEYS.IS_AUTHENTICATED) === 'true',

    setAuthenticated: (val: boolean): void =>
        val
            ? localStorage.setItem(KEYS.IS_AUTHENTICATED, 'true')
            : localStorage.removeItem(KEYS.IS_AUTHENTICATED),

    // ── Settings gate ────────────────────────────────────────────────────────
    isSettingsUnlocked: (): boolean =>
        localStorage.getItem(KEYS.SETTINGS_UNLOCKED) === 'true',

    setSettingsUnlocked: (val: boolean): void =>
        val
            ? localStorage.setItem(KEYS.SETTINGS_UNLOCKED, 'true')
            : localStorage.removeItem(KEYS.SETTINGS_UNLOCKED),

    // ── Env vars (.env config) ───────────────────────────────────────────────
    getEnvConfig: (): EnvConfig | null =>
        safeGet<EnvConfig>(KEYS.ENV_CONFIG),

    setEnvConfig: (config: EnvConfig): void =>
        safeSet(KEYS.ENV_CONFIG, config),

    // ── Public config (GET /api/config response) ─────────────────────────────
    getPublicConfig: (): Config | null =>
        safeGet<Config>(KEYS.PUBLIC_CONFIG),

    setPublicConfig: (config: Config): void =>
        safeSet(KEYS.PUBLIC_CONFIG, config),

    // ── Clear everything on logout ───────────────────────────────────────────
    clearAll: (): void =>
        Object.values(KEYS).forEach(k => localStorage.removeItem(k)),
};
