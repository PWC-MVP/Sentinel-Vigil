import { useState, useRef, useEffect, useCallback } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faRobot,
    faSearch,
    faShieldHalved,
    faGlobe,
    faBolt,
    faChartPie,
    faLock,
    faTrash,
    faStop,
    faArrowUp,
    faCircleCheck,
    faPlus,
    faPaperclip,
    faFilePdf,
    faFileCode
} from '@fortawesome/free-solid-svg-icons';

// ── Markdown renderer (simple, no deps) ─────────────────────────────────────
function renderMarkdown(text: string): string {
    // 1. Pre-process Tables
    const lines = text.split('\n');
    let inTable = false;
    let tableLines: string[] = [];
    const processedLines: string[] = [];

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.match(/^\|.*?\|$/)) {
            if (!inTable) {
                inTable = true;
                tableLines = [];
            }
            tableLines.push(line);
        } else {
            if (inTable) {
                processedLines.push(renderTable(tableLines));
                inTable = false;
            }
            processedLines.push(lines[i]);
        }
    }
    if (inTable) processedLines.push(renderTable(tableLines));

    text = processedLines.join('\n');

    // 2. Standard Markdown regex
    return text
        // Code blocks
        .replace(/```(\w*)\n?([\s\S]*?)```/g, (_m, _lang, code) =>
            `<pre><code>${escHtml(code.trim())}</code></pre>`)
        // Inline code
        .replace(/`([^`]+)`/g, (_m, c) => `<code>${escHtml(c)}</code>`)
        // Bold
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        // Italic
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        // H3
        .replace(/^### (.+)$/gm, '<h3>$1</h3>')
        // H2
        .replace(/^## (.+)$/gm, '<h2>$1</h2>')
        // H1
        .replace(/^# (.+)$/gm, '<h1>$1</h1>')
        // Unordered list items
        .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
        // Wrap consecutive <li> in <ul>
        .replace(/(<li>.*<\/li>\n?)+/g, s => `<ul>${s}</ul>`)
        // Horizontal rule
        .replace(/^---$/gm, '<hr/>')
        // Paragraphs (blank line separated)
        .replace(/\n\n+/g, '</p><p>')
        .replace(/^(?!<(?:h|u|p|pre|hr|table|thead|tbody|tr))/gm, '<p>')
        .replace(/$(?!.*<\/(?:h|u|p|pre|hr|table|thead|tbody|tr))/gm, '</p>');
}

function renderTable(lines: string[]): string {
    if (lines.length < 2) return lines.join('\n');

    const rows = lines.map(line =>
        line.slice(1, -1).split('|').map(c => c.trim())
    );

    // Extract headers (first row)
    const headers = rows[0];

    // Check if second row is a divider
    const hasDivider = rows[1]?.every(c => /^-+$/.test(c));
    const dataRows = hasDivider ? rows.slice(2) : rows.slice(1);

    const thead = `<thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>`;
    const tbody = `<tbody>${dataRows.map(row => `<tr>${row.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody>`;

    return `<table class="chat-table">${thead}${tbody}</table>`;
}

function escHtml(s: string) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ── Types ────────────────────────────────────────────────────────────────────
interface ChatMsg {
    id: string;
    role: 'user' | 'assistant';
    content: string;
    toolCalls?: { name: string; args: Record<string, unknown> }[];
    toolResults?: { name: string; result: string }[];
    streaming?: boolean;
}

interface SSEEvent {
    type: 'delta' | 'done' | 'error' | 'tool_call' | 'tool_result';
    content?: string;
    name?: string;
    args?: Record<string, unknown>;
    result?: string;
}

const SUGGESTIONS = [
    { label: 'Investigate user@contoso.com for the last 7 days', icon: faSearch },
    { label: 'Show me recent high-severity security incidents', icon: faShieldHalved },
    { label: 'Enrich these IPs: 1.2.3.4, 5.6.7.8', icon: faGlobe },
    { label: 'Hunt for AITM phishing signs in the last 14 days', icon: faBolt },
    { label: 'What anomalies were detected in the last 24 hours?', icon: faChartPie },
    { label: 'Check the Identity Protection risk detections today', icon: faLock },
];

let msgCounter = 0;
const uid = () => `msg-${++msgCounter}`;

export default function Chat() {
    const [toolCallExpanded, setToolCallExpanded] = useState<Record<string, boolean>>({});

    const toggleToolCall = (key: string) => {
        setToolCallExpanded(prev => ({ ...prev, [key]: !prev[key] }));
    };

    const [messages, setMessages] = useState<ChatMsg[]>([
        {
            id: uid(),
            role: 'assistant',
            content: `Hello! I'm **ARIA** — the Advanced Risk Intelligence Assistant built for the PwC Sentinel Engineering Team.

I have direct access to your **Microsoft Sentinel** workspace, **Microsoft Graph API**, and **threat intelligence APIs**.

Here's what I can do for you:
- **Investigate users** — full sign-in, anomaly, MFA, device, and incident analysis
- **Run KQL queries** — any ad-hoc Kusto query against your Sentinel workspace
- **Enrich IP addresses** — VPN/Tor detection, AbuseIPDB, Shodan
- **Threat hunting** — MITRE technique hunting, IOC analysis
- **Generate HTML reports** — professional investigation reports

What would you like to investigate?`,
        },
    ]);
    const [input, setInput] = useState('');
    const [streaming, setStreaming] = useState(false);
    const [llmStatus, setLlmStatus] = useState<{ available: boolean; provider?: string; model?: string; hint?: string } | null>(null);
    const [fileStatus, setFileStatus] = useState<{ name: string; type: string } | null>(null);
    const [fileContent, setFileContent] = useState<string | null>(null);
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLTextAreaElement>(null);
    const fileRef = useRef<HTMLInputElement>(null);
    const abortRef = useRef<AbortController | null>(null);

    // Auto-scroll
    const scrollToBottom = useCallback(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, []);

    useEffect(() => { scrollToBottom(); }, [messages, scrollToBottom]);

    // Check LLM status
    useEffect(() => {
        fetch('/api/chat/status')
            .then(r => r.json())
            .then(setLlmStatus)
            .catch(() => setLlmStatus({ available: false }));
    }, []);

    const sendMessage = useCallback(async (text: string) => {
        let contentToSend = text;
        if (fileContent) {
            contentToSend = `[DOCUMENT CONTENT: ${fileStatus?.name}]\n${fileContent}\n\n[USER QUERY]: ${text}`;
        }

        const userMsg: ChatMsg = { id: uid(), role: 'user', content: text };
        const assistantId = uid();
        const assistantMsg: ChatMsg = { id: assistantId, role: 'assistant', content: '', streaming: true, toolCalls: [], toolResults: [] };

        setMessages(prev => [...prev, userMsg, assistantMsg]);
        setInput('');
        setFileStatus(null);
        setFileContent(null);
        setStreaming(true);

        const history = [...messages.filter(m => !m.streaming), { ...userMsg, content: contentToSend }].map(m => ({
            role: m.role,
            content: m.content,
        }));

        const ctrl = new AbortController();
        abortRef.current = ctrl;

        try {
            const resp = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ messages: history }),
                signal: ctrl.signal,
            });

            if (!resp.ok) {
                throw new Error(`HTTP ${resp.status}`);
            }

            const reader = resp.body!.getReader();
            const decoder = new TextDecoder();

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split('\n');

                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    const data = line.slice(6).trim();
                    if (!data) continue;

                    try {
                        const evt: SSEEvent = JSON.parse(data);

                        setMessages(prev => prev.map(m => {
                            if (m.id !== assistantId) return m;

                            if (evt.type === 'delta' && evt.content) {
                                return { ...m, content: m.content + evt.content };
                            }
                            if (evt.type === 'tool_call' && evt.name) {
                                return { ...m, toolCalls: [...(m.toolCalls ?? []), { name: evt.name, args: evt.args ?? {} }] };
                            }
                            if (evt.type === 'tool_result' && evt.name) {
                                return { ...m, toolResults: [...(m.toolResults ?? []), { name: evt.name, result: evt.result ?? '' }] };
                            }
                            if (evt.type === 'done') {
                                return { ...m, streaming: false };
                            }
                            if (evt.type === 'error') {
                                return { ...m, content: m.content + `\n\n⚠️ **Error:** ${evt.content}`, streaming: false };
                            }
                            return m;
                        }));
                    } catch {
                        // ignore parse errors
                    }
                }
            }
        } catch (e: unknown) {
            if ((e as Error).name !== 'AbortError') {
                setMessages(prev => prev.map(m =>
                    m.id === assistantId
                        ? { ...m, content: `⚠️ Connection error: ${(e as Error).message}`, streaming: false }
                        : m
                ));
            }
        } finally {
            setStreaming(false);
            abortRef.current = null;
        }
    }, [messages, streaming]);

    const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage(input);
        }
    };

    const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            setFileStatus({ name: file.name, type: file.type });
            setFileContent(null);

            const isPdf = file.type === 'application/pdf' || file.name.endsWith('.pdf');
            const isText = file.type.startsWith('text/') ||
                file.name.endsWith('.kql') ||
                file.name.endsWith('.log') ||
                file.name.endsWith('.json') ||
                file.name.endsWith('.csv') ||
                file.name.endsWith('.yaml') ||
                file.name.endsWith('.yml') ||
                file.name.endsWith('.md');

            if (isPdf) {
                // Use backend for PDF parsing
                const originalInput = input;
                setInput(`[Parsing PDF: ${file.name}...] `);
                try {
                    const formData = new FormData();
                    formData.append('file', file);

                    const resp = await fetch('/api/chat/upload', {
                        method: 'POST',
                        body: formData
                    });
                    const data = await resp.json();

                    if (data.status === 'success') {
                        setFileContent(data.text);
                        setInput(`[Document Context: ${file.name} (${data.pages} pages) - Ready] ` + originalInput);
                    } else {
                        throw new Error(data.message || 'PDF parsing failed');
                    }
                } catch (err: any) {
                    alert(`PDF Error: ${err.message}`);
                    setFileStatus(null);
                    setInput(originalInput);
                }
            } else if (isText) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    const result = event.target?.result as string;
                    setFileContent(result);
                    setInput(prev => `[Document Context: ${file.name} - Ready] ` + prev);
                };
                reader.readAsText(file);
            } else {
                setInput(prev => prev + (prev.trim() ? '\n' : '') + `[Attached: ${file.name}] `);
            }
        }
        // Reset so the same file can be selected again
        if (fileRef.current) fileRef.current.value = '';
    };

    const adjustInputHeight = () => {
        if (inputRef.current) {
            inputRef.current.style.height = 'auto';
            inputRef.current.style.height = `${Math.min(inputRef.current.scrollHeight, 200)}px`;
        }
    };

    useEffect(() => {
        adjustInputHeight();
    }, [input]);

    const exportToPdf = async (content: string, id: string) => {
        try {
            const html = renderMarkdown(content);
            const resp = await fetch('/api/reports/export-pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    html: `<html><body>${html}</body></html>`,
                    filename: `Chat_Export_${id.slice(-4)}.pdf`
                })
            });
            if (!resp.ok) throw new Error('PDF export failed');
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `Chat_Export_${id.slice(-4)}.pdf`;
            a.click();
        } catch (e) {
            console.error(e);
            alert('Failed to export PDF');
        }
    };

    const exportToHtml = async (content: string, id: string) => {
        try {
            const html = renderMarkdown(content);
            const fullHtml = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Chat Export - ${id}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 40px auto; padding: 20px; }
        h1, h2, h3 { color: #000; margin-top: 24px; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #ddd; }
        code { font-family: "JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size: 0.9em; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f8f8; }
        ul, ol { padding-left: 20px; }
        .aria-brand { color: #E0301E; font-weight: bold; margin-bottom: 20px; border-bottom: 2px solid #E0301E; padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class="aria-brand">ARIA Security Investigation Report</div>
    ${html}
    <div style="margin-top: 40px; font-size: 0.8em; color: #888; border-top: 1px solid #eee; padding-top: 10px;">
        Generated by Sentinel Vigil ARIA Assistant · ${new Date().toLocaleString()}
    </div>
</body>
</html>`;

            const resp = await fetch('/api/reports/export-html', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    html: fullHtml,
                    filename: `Chat_Export_${id.slice(-4)}.html`
                })
            });
            if (!resp.ok) throw new Error('HTML export failed');
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `Chat_Export_${id.slice(-4)}.html`;
            a.click();
        } catch (e) {
            console.error(e);
            alert('Failed to export HTML');
        }
    };

    const stopStreaming = () => {
        abortRef.current?.abort();
        setStreaming(false);
        setMessages(prev => prev.map(m => m.streaming ? { ...m, streaming: false } : m));
    };

    const clearChat = () => {
        setMessages([{
            id: uid(), role: 'assistant',
            content: 'Chat cleared. How can I help you with your security investigation?',
        }]);
    };

    const isFirstMessage = messages.length <= 1;

    return (
        <div className="chat-page">
            {/* ── Header ──────────────────────────────────────── */}
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0 }}>
                <div>
                    <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <FontAwesomeIcon icon={faRobot} style={{ color: 'var(--brand)' }} />
                        <span>ARIA</span>
                        <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-muted)', marginLeft: 4 }}>
                            Advanced Risk Intelligence Assistant
                        </span>
                    </div>
                    <div className="page-subtitle">
                        {llmStatus === null ? 'Checking LLM status…' :
                            llmStatus.available
                                ? `Connected to ${llmStatus.provider} · ${llmStatus.model}`
                                : `⚠️ LLM not configured — ${llmStatus.hint}`}
                    </div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                    {streaming && (
                        <button className="btn btn-secondary btn-sm" onClick={stopStreaming}>
                            <FontAwesomeIcon icon={faStop} style={{ marginRight: 6 }} /> Stop
                        </button>
                    )}
                    <button className="btn btn-ghost btn-sm" onClick={clearChat}>
                        <FontAwesomeIcon icon={faTrash} style={{ marginRight: 6 }} /> Clear
                    </button>
                </div>
            </div>

            {/* ── LLM not configured warning ───────────────────── */}
            {llmStatus && !llmStatus.available && (
                <div style={{
                    margin: '12px 24px 0',
                    padding: '10px 16px',
                    background: 'rgba(192,57,43,0.08)',
                    border: '1px solid rgba(192,57,43,0.2)',
                    borderRadius: 'var(--radius-md)',
                    fontSize: 12,
                    color: 'var(--critical)',
                    flexShrink: 0,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10
                }}>
                    <span>⚠</span>
                    <span>AI assistant is currently unavailable. Check your LLM configuration in Settings.</span>
                </div>
            )}

            {/* ── Messages ─────────────────────────────────────── */}
            <div className="chat-messages">
                {messages.map(msg => (
                    <div key={msg.id} className={`chat-message ${msg.role}`}>
                        {msg.role === 'user' ? (
                            <div className="chat-avatar user" style={{ flexShrink: 0 }}>U</div>
                        ) : (
                            <div className="chat-avatar aria" style={{ flexShrink: 0 }}>A</div>
                        )}
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0, position: 'relative' }}>
                            {/* Tool calls — collapsible tool-call-section */}
                            {msg.toolCalls && msg.toolCalls.map((tc, i) => {
                                const tcKey = `${msg.id}-tc-${i}`;
                                const isExpanded = !!toolCallExpanded[tcKey];
                                const matchingResult = msg.toolResults?.[i];
                                return (
                                    <div key={i} className="tool-call-section">
                                        <div className="tool-call-header" onClick={() => toggleToolCall(tcKey)}>
                                            <span className="tool-call-name">{tc.name}</span>
                                            <span style={{ fontSize: 11, color: 'var(--pwc-orange)' }}>
                                                {isExpanded ? '▲ collapse' : '▼ expand'}
                                            </span>
                                        </div>
                                        {isExpanded && (
                                            <div className="tool-call-body">
                                                {Object.keys(tc.args).length > 0 && (
                                                    <pre style={{ margin: '0 0 8px', fontSize: 11 }}>
                                                        {JSON.stringify(tc.args, null, 2)}
                                                    </pre>
                                                )}
                                                {matchingResult && (
                                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', borderTop: '1px solid var(--border)', paddingTop: 6, marginTop: 4 }}>
                                                        <FontAwesomeIcon icon={faCircleCheck} style={{ color: 'var(--low)', marginRight: 6 }} />
                                                        {matchingResult.result.slice(0, 400)}{matchingResult.result.length > 400 ? '…' : ''}
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                            {/* Tool results not paired with tool calls */}
                            {msg.toolResults && msg.toolResults.slice(msg.toolCalls?.length ?? 0).map((tr, i) => (
                                <div key={`extra-${i}`} className="tool-call-section">
                                    <div className="tool-call-header">
                                        <span className="tool-call-name">{tr.name}</span>
                                        <FontAwesomeIcon icon={faCircleCheck} style={{ color: 'var(--low)', fontSize: 11 }} />
                                    </div>
                                </div>
                            ))}
                            {/* Message bubble */}
                            <div className={`chat-bubble ${msg.role}`}>
                                {msg.role === 'assistant' ? (
                                    <>
                                        {msg.content ? (
                                            <div dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }} />
                                        ) : null}
                                        {msg.streaming && !msg.content && (
                                            <div className="aria-typing">
                                                <div className="aria-typing-dot" />
                                                <div className="aria-typing-dot" />
                                                <div className="aria-typing-dot" />
                                            </div>
                                        )}
                                    </>
                                ) : (
                                    <span>{msg.content}</span>
                                )}
                            </div>

                            {/* Export buttons row at the bottom of the message */}
                            {msg.role === 'assistant' && !msg.streaming && msg.content && (
                                <div style={{ display: 'flex', gap: 12, marginTop: 8, paddingLeft: 4 }}>
                                    <button
                                        className="chat-action-btn"
                                        onClick={() => exportToPdf(msg.content, msg.id)}
                                        title="Export to PDF"
                                    >
                                        <FontAwesomeIcon icon={faFilePdf} style={{ marginRight: 6 }} />
                                        Export PDF
                                    </button>
                                    <button
                                        className="chat-action-btn"
                                        onClick={() => exportToHtml(msg.content, msg.id)}
                                        title="Export Decorated HTML"
                                    >
                                        <FontAwesomeIcon icon={faFileCode} style={{ marginRight: 6 }} />
                                        Export HTML
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>
                ))}
                {/* Typing indicator — shown when streaming but no assistant content yet from the last user message */}
                {streaming && messages.length > 0 && messages[messages.length - 1].role === 'user' && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 0' }}>
                        <div className="chat-avatar aria" style={{ flexShrink: 0 }}>A</div>
                        <div className="chat-bubble aria" style={{ padding: '10px 14px' }}>
                            <div className="aria-typing">
                                <div className="aria-typing-dot" />
                                <div className="aria-typing-dot" />
                                <div className="aria-typing-dot" />
                            </div>
                        </div>
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* ── Input area ─────────────────────────────────────── */}
            <div className="chat-input-area">
                {/* Suggestions (only on first message) */}
                {isFirstMessage && (
                    <div className="chat-suggestions">
                        {SUGGESTIONS.map((s, idx) => (
                            <button key={idx} className="chat-suggestion" onClick={() => sendMessage(s.label)}>
                                <FontAwesomeIcon icon={s.icon} style={{ marginRight: 6, opacity: 0.8 }} />
                                {s.label}
                            </button>
                        ))}
                    </div>
                )}
                {fileStatus && (
                    <div style={{ margin: '0 auto 10px', maxWidth: 900, display: 'flex', alignItems: 'center', gap: 8, width: 'fit-content' }}>
                        <span className="badge badge-muted" style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', borderRadius: 20, fontSize: 11 }}>
                            <FontAwesomeIcon icon={faPaperclip} />
                            <span>Attached: <strong>{fileStatus.name}</strong></span>
                            <button
                                className="btn btn-ghost btn-sm"
                                style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: '0 2px', minWidth: 'unset', height: 'unset' }}
                                onClick={() => {
                                    setFileStatus(null);
                                    setFileContent(null);
                                    if (fileRef.current) fileRef.current.value = '';
                                }}
                            >
                                ×
                            </button>
                        </span>
                    </div>
                )}
                <div className="chat-input-row">
                    <button
                        className="btn btn-ghost btn-sm chat-attach-btn"
                        onClick={() => fileRef.current?.click()}
                        title="Upload document"
                        style={{ height: 44, width: 44, borderRadius: '50%', flexShrink: 0 }}
                    >
                        <FontAwesomeIcon icon={faPlus} />
                    </button>
                    <input
                        type="file"
                        ref={fileRef}
                        style={{ display: 'none' }}
                        accept=".pdf,.txt,.log,.kql,.json,.csv,.yaml,.yml,.md"
                        onChange={handleFileChange}
                    />
                    <textarea
                        ref={inputRef}
                        className="chat-input"
                        placeholder="Ask ARIA anything — investigate a user, run KQL, hunt for threats…  (Enter to send, Shift+Enter for new line)"
                        value={input}
                        onChange={e => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        rows={1}
                        disabled={streaming}
                    />
                    <button
                        className="chat-send-btn"
                        onClick={() => sendMessage(input)}
                        disabled={streaming || !input.trim()}
                        title="Send (Enter)"
                    >
                        {streaming ? (
                            <div className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />
                        ) : (
                            <FontAwesomeIcon icon={faArrowUp} />
                        )}
                    </button>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6, textAlign: 'center' }}>
                    ARIA can make mistakes. Always verify critical findings in Microsoft Sentinel before taking action.
                </div>
            </div>
        </div>
    );
}
