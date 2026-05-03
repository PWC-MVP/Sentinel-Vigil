import axios from 'axios';

const api = axios.create({
    baseURL: '/api',
    timeout: 10000,   // 10 s — fail fast when backend is down instead of hanging forever
});

// Use this in pages that call full /api/... paths (no baseURL, but has timeout)
export const http = axios.create({ timeout: 10000 });

// ── Types ───────────────────────────────────────────────────────────────────

export interface Config {
    sentinel_workspace_id: string;
    workspace_name: string;
    tenant_id: string;
    subscription_id: string;
    resource_group: string;
    output_dir: string;
    apis_configured: Record<string, boolean>;
    config_valid: boolean;
    auth: {
        authenticated: boolean;
        method?: string;
        error?: string;
        hint?: string;
    };
}

export interface Job {
    job_id: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    created_at: string;
    completed_at?: string;
    error?: string;
    result?: InvestigationResult;
    updates: JobUpdate[];
}

export interface JobUpdate {
    phase: string;
    message: string;
    timestamp: string;
    data?: unknown;
}

export interface InvestigationResult {
    upn: string;
    user_id: string;
    investigation_date: string;
    start_date: string;
    end_date: string;
    user_profile?: UserProfile;
    mfa_status?: MFAStatus;
    devices: Device[];
    risk_profile?: RiskProfile;
    risk_detections: RiskDetection[];
    risky_signins: RiskySignIn[];
    anomalies: AnomalyRow[];
    signin_events: SigninEvents;
    audit_events: AuditRow[];
    office_events: OfficeRow[];
    cloud_app_events: CloudAppEventRow[];
    incidents: IncidentRow[];
    ip_intelligence: IPIntelligence[];
    threat_intel: ThreatRow[];
    risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    risk_factors: string[];
    mitigating_factors: string[];
    report_path?: string;
    ai_summary?: string;
}

export interface UserProfile {
    display_name: string;
    upn: string;
    job_title: string;
    department: string;
    office_location: string;
    account_enabled: boolean;
    user_type: string;
}

export interface MFAStatus {
    mfa_enabled: boolean;
    methods_count: number;
    methods: string[];
    has_fido2: boolean;
    has_authenticator: boolean;
}

export interface Device {
    displayName?: string;
    operatingSystem?: string;
    isCompliant?: boolean;
    trustType?: string;
    approximateLastSignInDateTime?: string;
}

export interface RiskProfile {
    riskState?: string;
    riskLevel?: string;
}

export interface RiskDetection {
    riskEventType?: string;
    riskLevel?: string;
    riskState?: string;
    detectedDateTime?: string;
    ipAddress?: string;
}

export interface RiskySignIn {
    createdDateTime?: string;
    appDisplayName?: string;
    riskState?: string;
    riskLevelDuringSignIn?: string;
}

export interface AnomalyRow {
    DetectedDateTime?: string;
    AnomalyType?: string;
    Value?: string;
    Severity?: string;
    Country?: string;
    City?: string;
    CountryNovelty?: boolean;
    ArtifactHits?: number;
}

export interface SigninEvents {
    applications: AppSignin[];
    locations: LocationSignin[];
    failures: FailureRow[];
    total_signins: number;
    total_failures: number;
}

export interface AppSignin {
    AppDisplayName?: string;
    SignInCount?: number;
    SuccessCount?: number;
    FailureCount?: number;
    LastSeen?: string;
}

export interface LocationSignin {
    Location?: string;
    SignInCount?: number;
    FailureCount?: number;
}

export interface FailureRow {
    ResultType?: string;
    ResultDescription?: string;
    FailureCount?: number;
}

export interface AuditRow {
    Category: string;
    Result: string;
    Count: number;
    FirstSeen?: string;
    LastSeen?: string;
    Operations?: string[];
}

export interface OfficeRow {
    RecordType: string;
    Operation: string;
    ActivityCount: number;
}

export interface CloudAppEventRow {
    ActionType: string;
    Application: string;
    Count: number;
    IsAdmin?: boolean;
    IsExternal?: boolean;
}

export interface IncidentRow {
    ProviderIncidentId?: string;
    Title?: string;
    Severity?: string;
    Status?: string;
    CreatedTime?: string;
    ProviderIncidentUrl?: string;
}

export interface IPIntelligence {
    ip: string;
    city?: string;
    region?: string;
    country?: string;
    org?: string;
    asn?: string;
    is_vpn?: boolean;
    is_tor?: boolean;
    is_proxy?: boolean;
    abuse_confidence_score?: number;
    total_reports?: number;
    threat_detected?: boolean;
    threat_description?: string;
    anomaly_type?: string;
    risk_level?: string;
    lat?: number;
    lon?: number;
}

export interface ThreatRow {
    IPAddress?: string;
    ThreatDescription?: string;
    Confidence?: number;
}

export interface Report {
    name: string;
    relative_path: string;
    size_bytes: number;
    created: number;
    subdirectory: string;
}

export interface KQLResult {
    columns: string[];
    rows: Record<string, unknown>[];
    row_count: number;
}

export interface BackupRequest {
    resource_types?: string[];
    output_dir?: string;
    incremental?: boolean;
}

export interface RestoreRequest {
    snapshot_path: string;
    resource_types?: string[];
    target_workspace?: string;
    target_subscription?: string;
    target_rg?: string;
    dry_run?: boolean;
}

export interface BackupSnapshot {
    snapshot_path: string;
    timestamp: string;
    incremental?: boolean;
    results?: Record<string, number | string>;
    manifest_summary?: {
        total_resources: number;
        by_type: Record<string, number>;
        manifest_path: string;
    };
}

export interface SnapshotDiff {
    added: string[];
    removed: string[];
    changed: string[];
    unchanged: number;
}

// ── API Methods ──────────────────────────────────────────────────────────────

export const getConfig = (): Promise<Config> =>
    api.get<Config>('/config').then(r => r.data);

export interface InvestigationOptions {
    include_cloud?: boolean;
    include_office?: boolean;
    include_audit?: boolean;
    include_identity?: boolean;
    generate_summary?: boolean;
}

export const startInvestigation = (
    upn: string, days_back: number, output_mode: string, options?: InvestigationOptions
): Promise<{ job_id: string }> =>
    api.post<{ job_id: string }>('/investigations', {
        upn, days_back, output_mode, ...options
    }).then(r => r.data);

export const getInvestigation = (job_id: string): Promise<Job> =>
    api.get<Job>(`/investigations/${job_id}`).then(r => r.data);

export const listInvestigations = (): Promise<{ investigations: Job[] }> =>
    api.get<{ investigations: Job[] }>('/investigations').then(r => r.data);

export const listReports = (): Promise<{ reports: Report[]; report_dir: string }> =>
    api.get<{ reports: Report[]; report_dir: string }>('/reports').then(r => r.data);

export const runKQL = (query: string, days: number): Promise<KQLResult> =>
    api.post<KQLResult>('/kql', { query, days }).then(r => r.data);

export const startEnrichment = (ips: string[]): Promise<{ job_id: string }> =>
    api.post<{ job_id: string }>('/enrich/ips', { ips }).then(r => r.data);

export const getEnrichment = (job_id: string) =>
    api.get(`/enrich/ips/${job_id}`).then(r => r.data);

export const startBackup = (req: BackupRequest): Promise<{ job_id: string }> =>
    api.post<{ job_id: string }>('/backup', req).then(r => r.data);

export const listSnapshots = (): Promise<{ snapshots: BackupSnapshot[] }> =>
    api.get<{ snapshots: BackupSnapshot[] }>('/backup/snapshots').then(r => r.data);

export const compareSnapshots = (snapshot_a: string, snapshot_b: string): Promise<SnapshotDiff> =>
    api.post<SnapshotDiff>('/backup/compare', { snapshot_a, snapshot_b }).then(r => r.data);

export const startRestore = (req: RestoreRequest): Promise<{ job_id: string }> =>
    api.post<{ job_id: string }>('/restore', req).then(r => r.data);

export const createInvestigationWS = (job_id: string): WebSocket => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return new WebSocket(`${proto}//${window.location.host}/api/investigations/ws/${job_id}`);
};

export default api;
