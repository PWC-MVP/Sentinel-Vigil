import { useState, useEffect } from 'react';
import { listSnapshots, startRestore } from '../api/client';
import type { BackupSnapshot } from '../api/client';

export default function Restore() {
    const [snapshots, setSnapshots] = useState<BackupSnapshot[]>([]);
    const [selected, setSelected]   = useState<string>('');
    const [dryRun, setDryRun]       = useState(true);
    const [running, setRunning]     = useState(false);
    const [result, setResult]       = useState<string | null>(null);
    const [error, setError]         = useState<string | null>(null);

    useEffect(() => {
        listSnapshots().then(r => setSnapshots(r.snapshots)).catch(() => {});
    }, []);

    const handleRestore = async () => {
        if (!selected) return;
        setRunning(true);
        setError(null);
        setResult(null);
        try {
            const { job_id } = await startRestore({
                snapshot_path: selected,
                dry_run: dryRun,
            });
            setResult(`Restore job started: ${job_id}`);
        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : 'Unknown error');
        } finally {
            setRunning(false);
        }
    };

    return (
        <div className="page-content">
            <h1 className="page-title">Restore Workspace</h1>

            <div className="card">
                <label className="form-label">Select Snapshot</label>
                <select
                    className="form-input"
                    value={selected}
                    onChange={e => setSelected(e.target.value)}
                >
                    <option value="">— Choose a snapshot —</option>
                    {snapshots.map(s => (
                        <option key={s.snapshot_path} value={s.snapshot_path}>
                            {s.timestamp} ({s.manifest_summary?.total_resources ?? '?'} resources)
                        </option>
                    ))}
                </select>
            </div>

            <div className="card">
                <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <input
                        type="checkbox"
                        checked={dryRun}
                        onChange={e => setDryRun(e.target.checked)}
                    />
                    Dry Run (preview changes without applying)
                </label>
            </div>

            {!dryRun && (
                <div className="alert alert-warning" style={{ marginBottom: 12 }}>
                    Warning: This will overwrite existing Sentinel resources. Make a fresh backup first.
                </div>
            )}

            <button
                className="btn btn-danger"
                onClick={handleRestore}
                disabled={!selected || running}
            >
                {running ? 'Running…' : dryRun ? 'Preview Restore' : 'Restore Now'}
            </button>

            {result && <p style={{ color: 'var(--success)', marginTop: 12 }}>{result}</p>}
            {error  && <p style={{ color: 'var(--danger)',  marginTop: 12 }}>{error}</p>}
        </div>
    );
}
