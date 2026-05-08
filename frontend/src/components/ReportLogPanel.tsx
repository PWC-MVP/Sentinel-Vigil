import { useEffect, useRef, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faSpinner, faCheckCircle, faTriangleExclamation,
    faRobot, faChevronRight,
} from '@fortawesome/free-solid-svg-icons';

export type LogStepLevel = 'info' | 'ai';

export interface LogStep {
    level: LogStepLevel;
    msg: string;
    delay: number; // ms after generate() is called
}

interface Props {
    steps: LogStep[];
    loading: boolean;
    success: boolean | null; // null = not started
    error: string | null;
    successMsg?: string;
}

export function ReportLogPanel({ steps, loading, success, error, successMsg = 'Report generated successfully' }: Props) {
    const [visibleCount, setVisibleCount] = useState(0);
    const [showWaiting, setShowWaiting]   = useState(false);
    const logEndRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!loading) return;
        setVisibleCount(0);
        setShowWaiting(false);

        const timers: ReturnType<typeof setTimeout>[] = [];
        steps.forEach((step, i) => {
            timers.push(setTimeout(() => {
                setVisibleCount(i + 1);
                logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
            }, step.delay));
        });
        const lastDelay = steps[steps.length - 1]?.delay ?? 0;
        timers.push(setTimeout(() => setShowWaiting(true), lastDelay + 400));
        return () => timers.forEach(clearTimeout);
    }, [loading]); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        if (!loading && success !== null) {
            setVisibleCount(steps.length);
            setShowWaiting(false);
        }
    }, [loading, success, steps.length]);

    if (!loading && success === null) return null;

    const isRunning = loading;
    const isDone    = !loading && success === true;
    const isFailed  = !loading && success === false;

    return (
        <div style={{
            marginTop: 16,
            border: '1px solid var(--border)',
            borderRadius: 10,
            overflow: 'hidden',
            background: 'var(--bg-surface)',
            boxShadow: '0 1px 4px rgba(0,0,0,0.06)',
        }}>
            {/* ── Header ── */}
            <div style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '10px 16px',
                background: 'var(--pwc-pale-grey)',
                borderBottom: '1px solid var(--border)',
            }}>
                {/* Status dot */}
                <div style={{
                    width: 9, height: 9, borderRadius: '50%', flexShrink: 0,
                    background: isFailed ? 'var(--critical)' : isRunning ? 'var(--pwc-orange)' : 'var(--low)',
                    color:      isFailed ? 'var(--critical)' : isRunning ? 'var(--pwc-orange)' : 'var(--low)',
                }} className={isRunning ? 'engine-dot-active' : ''} />

                <FontAwesomeIcon icon={faRobot} style={{ color: 'var(--pwc-orange)', fontSize: 12 }} />

                <span style={{
                    fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                    letterSpacing: '0.08em', color: 'var(--text-secondary)',
                }}>
                    AI Report Engine
                </span>

                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
                    {isRunning && (
                        <span style={{
                            fontSize: 11, color: 'var(--pwc-orange)', fontWeight: 600,
                            display: 'flex', alignItems: 'center', gap: 5,
                        }}>
                            <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 10 }} />
                            Processing…
                        </span>
                    )}
                    {isDone && (
                        <span style={{
                            fontSize: 11, color: 'var(--low)', fontWeight: 700,
                            display: 'flex', alignItems: 'center', gap: 5,
                        }}>
                            <FontAwesomeIcon icon={faCheckCircle} style={{ fontSize: 10 }} />
                            Complete
                        </span>
                    )}
                    {isFailed && (
                        <span style={{
                            fontSize: 11, color: 'var(--critical)', fontWeight: 700,
                            display: 'flex', alignItems: 'center', gap: 5,
                        }}>
                            <FontAwesomeIcon icon={faTriangleExclamation} style={{ fontSize: 10 }} />
                            Failed
                        </span>
                    )}
                </div>
            </div>

            {/* ── Log body ── */}
            <div style={{
                padding: '12px 16px',
                display: 'flex', flexDirection: 'column', gap: 0,
                maxHeight: 260, overflowY: 'auto',
                background: 'var(--bg-surface)',
            }}>
                {steps.slice(0, visibleCount).map((step, i) => (
                    <div key={i} className="log-item" style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '5px 0',
                        borderBottom: i < visibleCount - 1 ? '1px solid var(--border-subtle)' : 'none',
                    }}>
                        {step.level === 'info' ? (
                            <FontAwesomeIcon
                                icon={faChevronRight}
                                style={{ fontSize: 9, color: 'var(--pwc-orange)', flexShrink: 0, width: 12 }}
                            />
                        ) : (
                            <FontAwesomeIcon
                                icon={faRobot}
                                style={{ fontSize: 10, color: 'var(--pwc-orange)', flexShrink: 0, width: 12 }}
                            />
                        )}
                        <span style={{
                            fontSize: 12.5, lineHeight: 1.5,
                            color: step.level === 'ai' ? 'var(--pwc-orange)' : 'var(--text-secondary)',
                            fontWeight: step.level === 'ai' ? 500 : 400,
                        }}>
                            {step.msg}
                        </span>
                    </div>
                ))}

                {/* Pulsing waiting row */}
                {showWaiting && isRunning && (
                    <div className="log-item" style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '5px 0',
                    }}>
                        <FontAwesomeIcon
                            icon={faRobot}
                            style={{ fontSize: 10, color: 'var(--pwc-orange)', flexShrink: 0, width: 12 }}
                        />
                        <span style={{
                            fontSize: 12.5, color: 'var(--pwc-orange)', fontWeight: 500,
                            display: 'flex', alignItems: 'center', gap: 7,
                        }}>
                            <FontAwesomeIcon icon={faSpinner} spin style={{ fontSize: 10 }} />
                            Waiting for LLM response…
                        </span>
                    </div>
                )}

                {/* Success row */}
                {isDone && (
                    <div className="log-item" style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '7px 10px', marginTop: 8,
                        background: 'rgba(39,174,96,0.07)',
                        border: '1px solid rgba(39,174,96,0.22)',
                        borderRadius: 6,
                    }}>
                        <FontAwesomeIcon icon={faCheckCircle} style={{ fontSize: 11, color: 'var(--low)', flexShrink: 0 }} />
                        <span style={{ fontSize: 12.5, color: 'var(--low)', fontWeight: 600 }}>{successMsg}</span>
                    </div>
                )}

                {/* Error row */}
                {isFailed && (
                    <div className="log-item" style={{
                        display: 'flex', alignItems: 'flex-start', gap: 10,
                        padding: '7px 10px', marginTop: 8,
                        background: 'rgba(192,57,43,0.06)',
                        border: '1px solid rgba(192,57,43,0.22)',
                        borderRadius: 6,
                    }}>
                        <FontAwesomeIcon icon={faTriangleExclamation} style={{ fontSize: 11, color: 'var(--critical)', flexShrink: 0, marginTop: 1 }} />
                        <span style={{ fontSize: 12.5, color: 'var(--critical)', fontWeight: 500, lineHeight: 1.5 }}>
                            {error ?? 'Generation failed'}
                        </span>
                    </div>
                )}

                <div ref={logEndRef} />
            </div>
        </div>
    );
}
