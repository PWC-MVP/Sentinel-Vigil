import { useEffect, useState } from 'react';
import { listSnapshots, compareSnapshots } from '../api/client';
import type { BackupSnapshot, SnapshotDiff } from '../api/client';

export default function Snapshots() {
    const [snapshots, setSnapshots] = useState<BackupSnapshot[]>([]);
    const [loading, setLoading]     = useState(true);
    const [selected, setSelected]   = useState<string[]>([]);
    const [diff, setDiff]           = useState<SnapshotDiff | null>(null);
    const [diffError, setDiffError] = useState<string | null>(null);

    useEffect(() => {
        listSnapshots()
            .then(r => setSnapshots(r.snapshots))
            .catch(() => {})
            .finally(() => setLoading(false));
    }, []);

    const handleSelect = (path: string) => {
        setSelected(s => {
            if (s.includes(path)) return s.filter(p => p !== path);
            if (s.length >= 2)    return [s[1], path];
            return [...s, path];
        });
    };

    const handleCompare = async () => {
        if (selected.length !== 2) return;
        setDiffError(null);
        try {
            const result = await compareSnapshots(selected[0], selected[1]);
            setDiff(result);
        } catch (e: unknown) {
            setDiffError(e instanceof Error ? e.message : 'Compare failed');
        }
    };

    if (loading) return <div className="page-content"><p>Loading snapshots…</p></div>;

    return (
        <div className="page-content">
            <h1 className="page-title">Backup Snapshots</h1>

            <div className="card">
                <p className="hint">Select 2 snapshots to compare them.</p>

                {snapshots.length === 0 ? (
                    <p style={{ color: 'var(--text-secondary)' }}>No snapshots found. Run a backup first.</p>
                ) : (
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th></th>
                                <th>Timestamp</th>
                                <th>Total Resources</th>
                                <th>Incremental</th>
                            </tr>
                        </thead>
                        <tbody>
                            {snapshots.map(s => (
                                <tr key={s.snapshot_path}>
                                    <td>
                                        <input
                                            type="checkbox"
                                            checked={selected.includes(s.snapshot_path)}
                                            onChange={() => handleSelect(s.snapshot_path)}
                                        />
                                    </td>
                                    <td>{s.timestamp}</td>
                                    <td>{s.manifest_summary?.total_resources ?? '—'}</td>
                                    <td>{s.incremental ? 'Yes' : 'No'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}

                <button
                    className="btn btn-secondary"
                    onClick={handleCompare}
                    disabled={selected.length !== 2}
                    style={{ marginTop: 12 }}
                >
                    Compare Selected
                </button>
                {diffError && <p style={{ color: 'var(--danger)', marginTop: 8 }}>{diffError}</p>}
            </div>

            {diff && (
                <div className="card">
                    <h2 className="card-title">Diff Result</h2>
                    <p><strong>Added:</strong> {diff.added.length} resources</p>
                    <p><strong>Removed:</strong> {diff.removed.length} resources</p>
                    <p><strong>Changed:</strong> {diff.changed.length} resources</p>
                    <p><strong>Unchanged:</strong> {diff.unchanged} resources</p>
                    {diff.changed.length > 0 && (
                        <details style={{ marginTop: 8 }}>
                            <summary>Changed resources ({diff.changed.length})</summary>
                            <ul style={{ marginTop: 4 }}>
                                {diff.changed.map(r => <li key={r}>{r}</li>)}
                            </ul>
                        </details>
                    )}
                </div>
            )}
        </div>
    );
}
