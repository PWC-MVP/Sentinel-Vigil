import { useState } from 'react';
import { startBackup, getEnrichment } from '../api/client';

const RESOURCE_TYPES = [
    'scheduledRules', 'nrtRules', 'fusionRules', 'microsoftRules',
    'automationRules', 'workbooks', 'watchlists', 'huntingQueries',
    'summaryRules', 'dataConnectors', 'threatIntelligence', 'metadata',
];

export default function Backup() {
    const [selected, setSelected] = useState<string[]>([]);
    const [incremental, setIncremental] = useState(true);
    const [running, setRunning] = useState(false);
    const [jobId, setJobId] = useState<string | null>(null);
    const [status, setStatus] = useState<string>('');
    const [error, setError] = useState<string | null>(null);

    const toggle = (type: string) =>
        setSelected(s => s.includes(type) ? s.filter(t => t !== type) : [...s, type]);

    const handleStart = async () => {
        setRunning(true);
        setError(null);
        setStatus('');
        try {
            const { job_id } = await startBackup({
                resource_types: selected.length > 0 ? selected : undefined,
                incremental,
            });
            setJobId(job_id);
            setStatus('Backup started…');

            const poll = setInterval(async () => {
                try {
                    const job = await getEnrichment(job_id);
                    if (job.status === 'completed') {
                        setStatus('Backup complete!');
                        clearInterval(poll);
                        setRunning(false);
                    } else if (job.status === 'failed') {
                        setError(job.error || 'Backup failed');
                        clearInterval(poll);
                        setRunning(false);
                    }
                } catch {
                    // keep polling on transient errors
                }
            }, 2000);
        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : 'Unknown error');
            setRunning(false);
        }
    };

    return (
        <div className="page-content">
            <h1 className="page-title">Backup Workspace</h1>
            <p className="page-subtitle">
                Create a point-in-time snapshot of your Sentinel workspace configuration.
            </p>

            <div className="card">
                <h2 className="card-title">Resource Types</h2>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {RESOURCE_TYPES.map(t => (
                        <label key={t} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
                            <input
                                type="checkbox"
                                checked={selected.includes(t)}
                                onChange={() => toggle(t)}
                            />
                            {t}
                        </label>
                    ))}
                </div>
                <p className="hint" style={{ marginTop: 8 }}>Leave all unchecked to back up all resource types.</p>
            </div>

            <div className="card">
                <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <input
                        type="checkbox"
                        checked={incremental}
                        onChange={e => setIncremental(e.target.checked)}
                    />
                    Incremental (only changed resources since last snapshot)
                </label>
            </div>

            <button
                className="btn btn-primary"
                onClick={handleStart}
                disabled={running}
            >
                {running ? 'Running…' : 'Start Backup'}
            </button>

            {jobId && <p style={{ marginTop: 12 }}>Job ID: <code>{jobId}</code></p>}
            {status && <p style={{ color: 'var(--success)', marginTop: 8 }}>{status}</p>}
            {error  && <p style={{ color: 'var(--danger)',  marginTop: 8 }}>{error}</p>}
        </div>
    );
}
