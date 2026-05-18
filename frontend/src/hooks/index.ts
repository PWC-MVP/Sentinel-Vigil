import { useState, useEffect, useCallback } from 'react';
import { getConfig, listInvestigations, listReports, type Config, type Job, type Report } from '../api/client';
export type { Report };

/* ── useConfig ─────────────────────────────────────────────────────────── */
export function useConfig() {
    const [config, setConfig] = useState<Config | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        getConfig()
            .then(c => { setConfig(c); setError(null); })
            .catch(e => setError(e.message || 'Failed to connect to backend'))
            .finally(() => setLoading(false));
    }, []);

    return { config, loading, error };
}

/* ── useInvestigations ──────────────────────────────────────────────────── */
export function useInvestigations(pollMs = 0) {
    const [jobs, setJobs] = useState<Job[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const refresh = useCallback(() => {
        listInvestigations()
            .then(r => { setJobs(r.investigations); setError(null); })
            .catch(e => setError(e.message || 'Failed to load investigations'));
    }, []);

    useEffect(() => {
        setLoading(true);
        listInvestigations()
            .then(r => { setJobs(r.investigations); setError(null); setLoading(false); })
            .catch(e => { setError(e.message || 'Failed to load investigations'); setLoading(false); });
    }, []);

    useEffect(() => {
        if (!pollMs) return;
        const id = setInterval(refresh, pollMs);
        return () => clearInterval(id);
    }, [pollMs, refresh]);

    return { jobs, loading, error, refresh };
}

/* ── useReports ─────────────────────────────────────────────────────────── */
export function useReports() {
    const [reports, setReports] = useState<Report[]>([]);
    const [reportDir, setReportDir] = useState('');
    const [loading, setLoading] = useState(true);

    const refresh = useCallback(() => {
        listReports().then(r => { setReports(r.reports); setReportDir(r.report_dir); }).catch(() => { });
    }, []);

    useEffect(() => {
        listReports()
            .then(r => { setReports(r.reports); setReportDir(r.report_dir); setLoading(false); })
            .catch(() => setLoading(false));
    }, []);

    return { reports, reportDir, loading, refresh };
}
