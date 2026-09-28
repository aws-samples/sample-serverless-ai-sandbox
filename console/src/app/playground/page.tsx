"use client";
import { useEffect, useState, useRef, useCallback } from "react";
import {
  createSession,
  getSession,
  type SessionSummary,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { useToast } from "@/components/toast";
import {
  Send,
  Loader2,
  Terminal,
  FileText,
  Code,
  GitBranch,
  Database,
  Zap,
  Play,
  RotateCcw,
  Copy,
  Check,
  FileEdit,
  FolderOpen,
  CheckCircle,
  AlertTriangle,
} from "lucide-react";
import Markdown from "react-markdown";

const EXAMPLES = [
  {
    id: "data-analysis",
    title: "Data Analysis",
    icon: Database,
    description: "Process CSV data and generate statistics",
    prompt:
      "Create a CSV file with sample sales data (date, product, quantity, price) for 20 rows, then write a Python script to analyze it: total revenue, top product, monthly trend. Run the script and show results.",
  },
  {
    id: "code-gen",
    title: "Code Generation",
    icon: Code,
    description: "Generate and test a Python module",
    prompt:
      "Write a Python module that implements a simple key-value store with TTL (time-to-live) support. Include unit tests. Run the tests and show results.",
  },
  {
    id: "git-workflow",
    title: "Git Workflow",
    icon: GitBranch,
    description: "Initialize a repo and demonstrate git operations",
    prompt:
      "Initialize a git repo in /tmp/myproject, create a README.md and a main.py with a hello world function, commit them, create a feature branch, add a new function, and show the diff between branches.",
  },
  {
    id: "system-info",
    title: "System Exploration",
    icon: Terminal,
    description: "Explore the sandbox environment",
    prompt:
      "Explore this sandbox: show the OS info, installed tools (python, node, git, curl, jq versions), CPU/memory info, disk space, and list what's in /tmp. Summarize what this sandbox can do.",
  },
  {
    id: "file-processing",
    title: "File Processing",
    icon: FileText,
    description: "Transform and process files with jq",
    prompt:
      "Create a JSON file with nested data representing an e-commerce catalog (categories with products, each having name, price, stock), then use jq to extract: products under $50, out-of-stock items, and average price per category.",
  },
];

interface ToolExecution {
  tool: string;
  input: Record<string, string>;
  output: string;
  exitCode?: number;
  duration: number;
}

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  toolExecutions?: ToolExecution[];
  timestamp: Date;
}

export default function PlaygroundPage() {
  const [session, setSession] = useState<SessionSummary | null>(null);
  const [sessionLoading, setSessionLoading] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [executing, setExecuting] = useState(false);
  const chatRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const activityRef = useRef<HTMLDivElement>(null);
  const [activity, setActivity] = useState<Array<{id: number; time: string; actor: string; direction: string; detail: string; duration?: number}>>([]);
  const [connectId, setConnectId] = useState("");
  const [connecting, setConnecting] = useState(false);
  const { toast } = useToast();

  // Restore session from localStorage on mount
  useEffect(() => {
    const savedId = localStorage.getItem("playground-session-id");
    if (savedId && !session) {
      setReconnecting(true);
      getSession(savedId)
        .then((sess) => {
          if (sess.lifecycleState === "RUNNING" && sess.connection) {
            setSession(sess);
            // Restore chat history from localStorage
            const savedMsgs = localStorage.getItem("playground-messages");
            let restored: ChatMessage[] = [];
            if (savedMsgs) {
              try { restored = JSON.parse(savedMsgs); } catch { /* ignore */ }
            }
            setMessages([
              ...restored,
              {
                role: "assistant",
                content: restored.length > 0
                  ? `Reconnected to session \`${sess.sessionId.slice(0, 12)}...\`. Your previous conversation is restored.`
                  : `Reconnected to session \`${sess.sessionId.slice(0, 12)}...\`. Sandbox is running with all your files.`,
                timestamp: new Date(),
              },
            ]);
          } else {
            // Session no longer running — clear it
            localStorage.removeItem("playground-session-id");
          }
        })
        .catch(() => {
          localStorage.removeItem("playground-session-id");
        })
        .finally(() => setReconnecting(false));
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Persist messages to localStorage
  useEffect(() => {
    if (messages.length > 0) {
      localStorage.setItem("playground-messages", JSON.stringify(messages));
    }
  }, [messages]);

  useEffect(() => {
    chatRef.current?.scrollTo(0, chatRef.current.scrollHeight);
  }, [messages]);

  useEffect(() => {
    activityRef.current?.scrollTo(0, activityRef.current.scrollHeight);
  }, [activity]);

  const addActivity = useCallback((entry: {actor: string; direction: string; detail: string; duration?: number}) => {
    const now = new Date();
    const time = now.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
    setActivity(a => [...a, { ...entry, id: Date.now() + Math.random(), time }]);
  }, []);

  const startSession = useCallback(async () => {
    setSessionLoading(true);
    try {
      const created = await createSession();
      let sess = created;
      for (let i = 0; i < 30; i++) {
        if (sess.lifecycleState === "RUNNING" && sess.connection) break;
        await new Promise((r) => setTimeout(r, 3000));
        sess = await getSession(created.sessionId);
      }
      if (!sess.connection) throw new Error("Session did not become ready");
      setSession(sess);
      localStorage.setItem("playground-session-id", sess.sessionId);
      setMessages([
        {
          role: "assistant",
          content: `Sandbox ready! Session \`${sess.sessionId.slice(0, 12)}...\` is running.\n\nI can execute commands, write files, and run scripts in this sandbox. Try a prompt like:\n- "Set up a Python project with tests"\n- "Explore what tools are installed"\n- "Create a data pipeline"`,
          timestamp: new Date(),
        },
      ]);
      return sess;
    } catch (err) {
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: `Failed to create session: ${err}`,
          timestamp: new Date(),
        },
      ]);
      return null;
    } finally {
      setSessionLoading(false);
    }
  }, []);

  const connectToSession = useCallback(async (sessionId: string) => {
    if (!sessionId.trim()) return;
    setConnecting(true);
    try {
      let sess = await getSession(sessionId.trim());
      // If suspended, wait a moment — user might want to resume
      if (sess.lifecycleState === "SUSPENDED") {
        toast("Session is suspended. It will auto-resume on first command.", "info");
      }
      if (!sess.connection) {
        // Poll briefly in case it's still starting
        for (let i = 0; i < 15; i++) {
          if (sess.lifecycleState === "RUNNING" && sess.connection) break;
          await new Promise((r) => setTimeout(r, 2000));
          sess = await getSession(sessionId.trim());
        }
      }
      if (!sess.connection && !["RUNNING", "SUSPENDED"].includes(sess.lifecycleState)) {
        throw new Error(`Session is ${sess.lifecycleState} — cannot connect`);
      }
      setSession(sess);
      localStorage.setItem("playground-session-id", sess.sessionId);
      setMessages([{
        role: "assistant",
        content: `Connected to existing session \`${sess.sessionId.slice(0, 12)}...\` (${sess.lifecycleState}).\n\nThis sandbox is ready. Type a prompt to start working.`,
        timestamp: new Date(),
      }]);
      toast(`Connected to ${sess.sessionId.slice(0, 12)}...`, "success");
    } catch (err) {
      toast(`Failed to connect: ${err}`, "error");
    } finally {
      setConnecting(false);
    }
  }, [toast]);

  const sendPrompt = useCallback(
    async (prompt: string, sess?: SessionSummary | null) => {
      const activeSession = sess || session;
      if (!activeSession?.connection || executing) return;

      setExecuting(true);
      setMessages((m) => [
        ...m,
        { role: "user", content: prompt, timestamp: new Date() },
      ]);

      try {
        // Build conversation history for multi-turn
        const history = messages
          .filter((m) => !m.toolExecutions) // Only text messages
          .map((m) => ({ role: m.role, content: m.content }));

        addActivity({ actor: "you", direction: "request", detail: prompt.slice(0, 80) });

        const resp = await fetch("/api/playground", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prompt, connection: activeSession.connection, history, stream: true }),
        });

        if (resp.headers.get("content-type")?.includes("text/event-stream")) {
          const reader = resp.body?.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          let finalText = "";
          let finalTools: ToolExecution[] = [];

          while (reader) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() || "";
            let eventType = "";
            for (const line of lines) {
              if (line.startsWith("event: ")) eventType = line.slice(7).trim();
              else if (line.startsWith("data: ")) {
                try {
                  const data = JSON.parse(line.slice(6));
                  if (eventType === "activity") addActivity({ actor: data.actor, direction: data.direction, detail: data.detail, duration: data.duration });
                  else if (eventType === "done") { finalText = data.text || ""; finalTools = data.toolExecutions || []; }
                  else if (eventType === "error") finalText = "Error: " + data.message;
                } catch { /* ignore */ }
              }
            }
          }
          setMessages((m) => [...m, { role: "assistant", content: finalText || "Done.", toolExecutions: finalTools.length > 0 ? finalTools : undefined, timestamp: new Date() }]);
        } else {
          const data = await resp.json();
          if (data.error) setMessages((m) => [...m, { role: "assistant", content: "Error: " + data.error, timestamp: new Date() }]);
          else setMessages((m) => [...m, { role: "assistant", content: data.text || "Done.", toolExecutions: data.toolExecutions, timestamp: new Date() }]);
        }
      } catch (err) {
        setMessages((m) => [
          ...m,
          {
            role: "assistant",
            content: `Request failed: ${err}`,
            timestamp: new Date(),
          },
        ]);
      }

      setExecuting(false);
      inputRef.current?.focus();
    },
    [session, executing, messages, addActivity]
  );

  const handleSend = () => {
    if (!input.trim()) return;
    const prompt = input;
    setInput("");
    sendPrompt(prompt);
  };

  const handleExample = (prompt: string) => {
    setInput(prompt);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold">Interactive Playground</h1>
          <p className="text-gray-400 text-sm mt-1">
            Describe what you want — AI executes it in a live sandbox
          </p>
        </div>
        {session && (
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-500 font-mono">
              {session.sessionId.slice(0, 12)}...
            </span>
            <span className="px-2 py-0.5 rounded-full text-xs bg-green-900/50 text-green-400 border border-green-700">
              RUNNING
            </span>
            <button
              onClick={() => {
                setSession(null);
                setMessages([]);
                localStorage.removeItem("playground-session-id");
                localStorage.removeItem("playground-messages");
              }}
              className="p-1.5 rounded hover:bg-gray-800 text-gray-400"
              title="Reset session"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>

      {reconnecting ? (
        <div className="flex-1 flex flex-col items-center justify-center">
          <Loader2 className="w-8 h-8 animate-spin text-blue-400 mb-4" />
          <p className="text-gray-400 text-sm">Reconnecting to previous session...</p>
        </div>
      ) : !session ? (
        <div className="flex-1 flex flex-col items-center justify-center">
          <div className="text-center mb-8">
            <div className="w-16 h-16 bg-blue-600/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
              <Zap className="w-8 h-8 text-blue-400" />
            </div>
            <h2 className="text-xl font-semibold mb-2">
              AI-Powered Sandbox Playground
            </h2>
            <p className="text-gray-400 text-sm max-w-md">
              Describe a task in natural language. The AI will plan and execute
              commands in an isolated sandbox, showing you every step.
            </p>
          </div>
          <button
            onClick={startSession}
            disabled={sessionLoading}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-6 py-3 rounded-xl text-sm font-medium transition-colors"
          >
            {sessionLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" /> Creating
                sandbox...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" /> Start Sandbox
              </>
            )}
          </button>

          {/* Connect to existing session */}
          <div className="flex items-center gap-3 mt-6 w-full max-w-md">
            <div className="flex-1 h-px bg-[var(--border-primary)]" />
            <span className="text-xs text-[var(--text-muted)]">or connect to existing</span>
            <div className="flex-1 h-px bg-[var(--border-primary)]" />
          </div>
          <div className="flex gap-2 mt-3 w-full max-w-md">
            <input
              type="text"
              value={connectId}
              onChange={(e) => setConnectId(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && connectId.trim()) connectToSession(connectId); }}
              placeholder="Paste a session ID..."
              className="flex-1 bg-[var(--bg-secondary)] border border-[var(--border-secondary)] rounded-xl px-4 py-2.5 text-sm font-mono focus:outline-none focus:border-[var(--accent)] text-[var(--text-primary)] placeholder-[var(--text-muted)] transition-all"
            />
            <button
              onClick={() => connectToSession(connectId)}
              disabled={connecting || !connectId.trim()}
              className="bg-[var(--bg-tertiary)] hover:bg-[var(--border-secondary)] disabled:opacity-40 text-[var(--text-secondary)] px-4 py-2.5 rounded-xl text-sm font-medium transition-all"
            >
              {connecting ? <Loader2 className="w-4 h-4 animate-spin" /> : "Connect"}
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 mt-8 max-w-3xl w-full">
            {EXAMPLES.map((ex) => {
              const Icon = ex.icon;
              return (
                <button
                  key={ex.id}
                  onClick={() => { setInput(ex.prompt); startSession(); }}
                  disabled={sessionLoading}
                  className="text-left bg-gray-900 border border-gray-800 rounded-xl p-4 hover:border-gray-700 transition-colors disabled:opacity-50"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <Icon className="w-4 h-4 text-blue-400" />
                    <span className="text-sm font-medium">{ex.title}</span>
                  </div>
                  <p className="text-xs text-gray-500">{ex.description}</p>
                </button>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="flex-1 flex gap-3 min-h-0">
          <div className="flex-1 flex flex-col min-h-0">
          {/* Chat */}
          <div ref={chatRef} className="flex-1 overflow-y-auto space-y-4 pb-4">
            {messages.map((msg, i) => (
              <MessageBubble key={i} message={msg} sessionId={session?.sessionId} />
            ))}
            {executing && (
              <div className="flex items-center gap-2 text-blue-400 text-sm px-4 py-3 bg-blue-600/5 rounded-lg mx-4">
                <Loader2 className="w-4 h-4 animate-spin" />
                AI is thinking and executing in the sandbox...
              </div>
            )}
          </div>

          {/* Input */}
          <div className="border-t border-gray-800 bg-gray-900 rounded-xl p-3 mt-2">
            {messages.length <= 1 && !executing && (
              <div className="flex flex-wrap gap-2 mb-3">
                {EXAMPLES.map((ex) => (
                  <button
                    key={ex.id}
                    onClick={() => { setInput(ex.prompt); inputRef.current?.focus(); }}
                    disabled={executing}
                    className="text-xs bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 hover:border-gray-600 text-gray-400 hover:text-gray-300 transition-colors"
                  >
                    {ex.title}
                  </button>
                ))}
              </div>
            )}
            <div className="flex gap-2">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Describe what you want to do in the sandbox..."
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 resize-none min-h-[42px] max-h-[120px]"
                rows={1}
                disabled={executing}
              />
              <button
                onClick={handleSend}
                disabled={executing || !input.trim()}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 rounded-lg transition-colors self-end h-[42px]"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
            <p className="text-[10px] text-gray-600 mt-1.5">
              Powered by Claude Sonnet 5 on Amazon Bedrock. Press Enter to send, Shift+Enter for new line.
            </p>
          </div>
          </div>

          {/* Activity Panel */}
          <div className="w-72 bg-gray-900 border border-gray-800 rounded-xl flex flex-col min-h-0 shrink-0">
            <div className="flex items-center justify-between px-3 py-2 border-b border-gray-800">
              <span className="text-xs font-semibold text-gray-400">Activity Log</span>
              <button onClick={() => setActivity([])} className="text-[10px] text-gray-600 hover:text-gray-400">Clear</button>
            </div>
            <div ref={activityRef} className="flex-1 overflow-y-auto p-2 space-y-0.5 font-mono text-[11px]">
              {activity.length === 0 && (
                <p className="text-gray-600 text-center py-8 text-xs font-sans">
                  Activity will appear here<br/>as the AI thinks and executes.
                </p>
              )}
              {activity.map(a => (
                <div key={a.id} className={cn(
                  "px-1.5 py-0.5 rounded flex items-start gap-1",
                  a.actor === "bedrock" ? "text-purple-400" :
                  a.actor === "microvm" ? "text-orange-400" :
                  "text-blue-400"
                )}>
                  <span className="text-gray-600 shrink-0 text-[10px]">{a.time}</span>
                  <span className="shrink-0">{
                    a.actor === "bedrock" ? (a.direction === "request" ? "🧠→" : "🧠←") :
                    a.actor === "microvm" ? (a.direction === "request" ? "🔥→" : "🔥←") :
                    "💻→"
                  }</span>
                  <span className="break-all">{a.detail?.slice(0, 120)}{a.duration ? ` (${a.duration}ms)` : ""}</span>
                </div>
              ))}
              {executing && (
                <div className="flex items-center gap-1 text-purple-400 py-1 px-1.5">
                  <Loader2 className="w-3 h-3 animate-spin" /> Processing...
                </div>
              )}
            </div>
            <div className="px-3 py-2 border-t border-gray-800 text-[10px] text-gray-600 space-y-0.5">
              <div className="flex items-center gap-1.5">💻 <span className="text-blue-400">Your laptop</span></div>
              <div className="flex items-center gap-1.5">🧠 <span className="text-purple-400">Bedrock</span> (Claude)</div>
              <div className="flex items-center gap-1.5">🔥 <span className="text-orange-400">MicroVM</span> (sandbox)</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// --- Message bubble ---

function MessageBubble({ message, sessionId }: { message: ChatMessage; sessionId?: string }) {
  const [expanded, setExpanded] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  const copyText = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const toolIconMap: Record<string, React.ElementType> = {
    execute_command: Terminal,
    write_file: FileEdit,
    read_file: FileText,
    list_files: FolderOpen,
  };

  if (message.role === "user") {
    return (
      <div className="flex justify-end px-4">
        <div className="bg-blue-600/20 border border-blue-800 rounded-xl px-4 py-3 max-w-[80%]">
          <p className="text-sm text-blue-100 whitespace-pre-wrap">
            {message.content}
          </p>
        </div>
      </div>
    );
  }

  const hasTools = message.toolExecutions && message.toolExecutions.length > 0;
  const succeeded = message.toolExecutions?.filter((t) => t.exitCode === 0 || t.exitCode === undefined).length ?? 0;
  const totalTools = message.toolExecutions?.length ?? 0;
  const totalTime = message.toolExecutions?.reduce((s, t) => s + t.duration, 0) ?? 0;
  const allOk = succeeded === totalTools;

  return (
    <div className="px-4 space-y-3">
      {/* Text content — rendered as markdown */}
      {message.content && (
        <div className="prose prose-sm prose-invert max-w-none prose-pre:bg-gray-900 prose-pre:border prose-pre:border-gray-800 prose-code:text-green-400 prose-code:before:content-none prose-code:after:content-none">
          <Markdown>{message.content}</Markdown>
        </div>
      )}

      {/* Tool executions — summary bar + expandable details */}
      {hasTools && (
        <div className="space-y-2">
          {/* Summary bar */}
          <div
            className={cn(
              "flex items-center justify-between rounded-lg px-3 py-2 text-xs cursor-pointer transition-colors",
              allOk
                ? "bg-green-900/20 border border-green-900/50 hover:bg-green-900/30"
                : "bg-yellow-900/20 border border-yellow-900/50 hover:bg-yellow-900/30"
            )}
            onClick={() => setExpanded(!expanded)}
          >
            <div className="flex items-center gap-2">
              {allOk ? (
                <CheckCircle className="w-3.5 h-3.5 text-green-400" />
              ) : (
                <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />
              )}
              <span className={allOk ? "text-green-400" : "text-yellow-400"}>
                {totalTools} tool call{totalTools > 1 ? "s" : ""} completed
              </span>
              <span className="text-gray-600">
                {(totalTime / 1000).toFixed(1)}s
              </span>
            </div>
            <div className="flex items-center gap-2">
              {sessionId && (
                <a
                  href={`/sessions/${sessionId}`}
                  className="text-blue-400 hover:text-blue-300 underline"
                  onClick={(e) => e.stopPropagation()}
                >
                  Open session →
                </a>
              )}
              <span
                className={cn(
                  "transition-transform text-gray-500",
                  expanded ? "rotate-90" : ""
                )}
              >
                ▶
              </span>
            </div>
          </div>

          {/* Expanded tool details */}
          {expanded &&
            message.toolExecutions!.map((tc, i) => {
              const Icon = toolIconMap[tc.tool] || Terminal;
              const displayInput =
                tc.tool === "execute_command"
                  ? tc.input.command
                  : tc.tool === "write_file"
                    ? `${tc.input.path} (${tc.input.content?.length || 0} chars)`
                    : tc.tool === "read_file"
                      ? tc.input.path
                      : tc.input.path || JSON.stringify(tc.input);

              return (
                <div
                  key={i}
                  className="bg-black border border-gray-800 rounded-lg overflow-hidden"
                >
                  <div className="flex items-center justify-between px-3 py-2 border-b border-gray-800 bg-gray-900/50">
                    <div className="flex items-center gap-2 min-w-0">
                      <Icon className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                      <span className="text-xs font-mono text-gray-400 truncate">
                        {tc.tool}
                      </span>
                      {tc.exitCode !== undefined && (
                        <span
                          className={cn(
                            "text-[10px] px-1.5 py-0.5 rounded shrink-0",
                            tc.exitCode === 0
                              ? "bg-green-900/50 text-green-400"
                              : "bg-red-900/50 text-red-400"
                          )}
                        >
                          exit {tc.exitCode}
                        </span>
                      )}
                      <span className="text-[10px] text-gray-600 shrink-0">
                        {tc.duration}ms
                      </span>
                    </div>
                    <button
                      onClick={() => copyText(tc.output, i)}
                      className="p-1 rounded hover:bg-gray-800 text-gray-500 shrink-0"
                    >
                      {copiedIdx === i ? (
                        <Check className="w-3 h-3 text-green-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                  <div className="p-3">
                    <div className="text-xs text-green-400 font-mono mb-1 truncate">
                      {tc.tool === "execute_command" ? "$ " : ""}
                      {displayInput}
                    </div>
                    {tc.output && (
                      <pre className="text-xs text-gray-400 font-mono whitespace-pre-wrap break-all max-h-[250px] overflow-auto">
                        {tc.output.length > 2000
                          ? tc.output.slice(0, 2000) + "\n... (truncated)"
                          : tc.output}
                      </pre>
                    )}
                  </div>
                </div>
              );
            })}
        </div>
      )}
    </div>
  );
}

