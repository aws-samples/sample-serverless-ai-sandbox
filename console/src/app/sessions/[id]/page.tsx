"use client";
import { useEffect, useState, useCallback, useRef } from "react";
import { useParams } from "next/navigation";
import { getSession, suspendSession, resumeSession, terminateSession, executeCommand, listSandboxFiles, readSandboxFile, type SessionSummary } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Pause, Play, Trash2, RefreshCcw, Terminal, FolderOpen, Activity, File, Folder, ChevronRight, ArrowUp, Loader2, ScrollText, CheckCircle, Circle } from "lucide-react";
import { MetricsPanel } from "@/components/metrics-chart";
import { LogViewer } from "@/components/log-viewer";
import { PersistencePanel } from "@/components/persistence-panel";
import { useToast } from "@/components/toast";

const LIFECYCLE_STATES = ["ORCHESTRATING", "PROVISIONING", "STARTING", "RUNNING", "SUSPENDED", "TERMINATED"];
type TabId = "terminal" | "files" | "metrics" | "logs";

export default function SessionDetailPage() {
  const params = useParams();
  const sessionId = params.id as string;
  const [session, setSession] = useState<SessionSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<TabId>("terminal");
  const { toast } = useToast();

  const fetchSession = useCallback(() => {
    getSession(sessionId).then((data) => { setSession(data); setLoading(false); }).catch(() => setLoading(false));
  }, [sessionId]);

  useEffect(() => {
    fetchSession();
    const interval = setInterval(fetchSession, 5000);
    return () => clearInterval(interval);
  }, [fetchSession]);

  if (loading) return <div className="flex items-center justify-center h-64 text-[var(--text-muted)]"><Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading session...</div>;
  if (!session) return <div className="text-red-400 text-center py-12">Session not found</div>;

  const currentIdx = LIFECYCLE_STATES.indexOf(session.lifecycleState);
  const isConnected = !!session.connection;

  const tabs: { id: TabId; label: string; icon: React.ReactNode }[] = [
    { id: "terminal", label: "Terminal", icon: <Terminal className="w-4 h-4" /> },
    { id: "files", label: "Files", icon: <FolderOpen className="w-4 h-4" /> },
    { id: "metrics", label: "Metrics", icon: <Activity className="w-4 h-4" /> },
    { id: "logs", label: "Logs", icon: <ScrollText className="w-4 h-4" /> },
  ];

  const handleAction = async (action: "suspend" | "resume" | "terminate") => {
    try {
      if (action === "suspend") await suspendSession(sessionId);
      else if (action === "resume") await resumeSession(sessionId);
      else await terminateSession(sessionId);
      toast(`Session ${action}ed`, "success");
      fetchSession();
    } catch (err) {
      toast(`${action} failed: ${err}`, "error");
    }
  };

  return (
    <div className="max-w-6xl">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">Session Detail</h1>
          <p className="text-[var(--text-muted)] font-mono text-sm mt-1">{sessionId}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchSession} className="p-2.5 rounded-xl bg-[var(--bg-tertiary)] hover:bg-[var(--border-secondary)] text-[var(--text-muted)] transition-colors" title="Refresh">
            <RefreshCcw className="w-4 h-4" />
          </button>
          {session.lifecycleState === "RUNNING" && (
            <button onClick={() => handleAction("suspend")} className="flex items-center gap-2 bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 border border-yellow-500/20 px-4 py-2 rounded-xl text-sm font-medium transition-all">
              <Pause className="w-4 h-4" /> Suspend
            </button>
          )}
          {session.lifecycleState === "SUSPENDED" && (
            <button onClick={() => handleAction("resume")} className="flex items-center gap-2 bg-green-500/10 hover:bg-green-500/20 text-green-400 border border-green-500/20 px-4 py-2 rounded-xl text-sm font-medium transition-all">
              <Play className="w-4 h-4" /> Resume
            </button>
          )}
          {!["TERMINATED", "FAILED"].includes(session.lifecycleState) && (
            <button onClick={() => handleAction("terminate")} className="flex items-center gap-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 px-4 py-2 rounded-xl text-sm font-medium transition-all">
              <Trash2 className="w-4 h-4" /> Terminate
            </button>
          )}
        </div>
      </div>

      {/* Lifecycle Pipeline — step indicator */}
      <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-2xl p-6 mb-6">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-5">Lifecycle Pipeline</h2>
        <div className="flex items-center">
          {LIFECYCLE_STATES.map((state, idx) => {
            const isActive = state === session.lifecycleState;
            const isPast = idx < currentIdx;
            const isFailed = session.lifecycleState === "FAILED";
            return (
              <div key={state} className="flex items-center flex-1">
                <div className="flex flex-col items-center flex-1">
                  {/* Circle indicator */}
                  <div className={cn(
                    "w-8 h-8 rounded-full flex items-center justify-center transition-all duration-500",
                    isPast && "bg-green-500/20",
                    isActive && !isFailed && "bg-blue-500/20 ring-2 ring-blue-400/50 ring-offset-2 ring-offset-[var(--bg-secondary)]",
                    isActive && isFailed && "bg-red-500/20 ring-2 ring-red-400/50",
                    !isActive && !isPast && "bg-[var(--bg-tertiary)]",
                  )}>
                    {isPast ? (
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    ) : isActive ? (
                      <div className={cn("w-2.5 h-2.5 rounded-full", isFailed ? "bg-red-400" : "bg-blue-400 animate-pulse")} />
                    ) : (
                      <Circle className="w-4 h-4 text-[var(--text-muted)]/30" />
                    )}
                  </div>
                  {/* Label */}
                  <span className={cn(
                    "text-[10px] font-medium mt-2 transition-colors",
                    isActive ? (isFailed ? "text-red-400" : "text-blue-400") : isPast ? "text-green-400" : "text-[var(--text-muted)]/50"
                  )}>
                    {state}
                  </span>
                </div>
                {/* Connector line */}
                {idx < LIFECYCLE_STATES.length - 1 && (
                  <div className={cn(
                    "h-0.5 flex-1 -mx-1 transition-all duration-500",
                    isPast ? "bg-green-500/40" : "bg-[var(--border-primary)]"
                  )} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Info cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <InfoCard label="State" value={session.lifecycleState} />
        <InfoCard label="Tenant" value={session.tenantId || "operator"} />
        <InfoCard label="Endpoint" value={session.connection?.baseUrl ? new URL(session.connection.baseUrl).hostname.split(".")[0] + "..." : "Pending"} />
        <InfoCard label="Session" value={sessionId.slice(0, 16) + "..."} />
      </div>

      {/* Persistence */}
      {isConnected && (
        <div className="mb-6">
          <PersistencePanel connection={session.connection} />
        </div>
      )}

      {/* Tab bar */}
      <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-2xl overflow-hidden">
        <div className="flex border-b border-[var(--border-primary)] px-1">
          {tabs.map((tab) => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex items-center gap-2 px-4 py-3.5 text-sm font-medium transition-all relative",
                activeTab === tab.id ? "text-[var(--accent)]" : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              )}>
              {tab.icon}
              {tab.label}
              {activeTab === tab.id && (
                <span className="absolute bottom-0 left-2 right-2 h-0.5 bg-[var(--accent)] rounded-full" />
              )}
            </button>
          ))}
        </div>
        <div className="p-4">
          {!isConnected ? (
            <div className="text-[var(--text-muted)] text-sm py-12 text-center flex flex-col items-center gap-3">
              <Loader2 className="w-5 h-5 animate-spin" />
              Waiting for sandbox to be ready...
            </div>
          ) : (
            <>
              {activeTab === "terminal" && <TerminalPanel connection={session.connection} />}
              {activeTab === "files" && <FilesPanel connection={session.connection} />}
              {activeTab === "metrics" && <MetricsPanel connection={session.connection} />}
              {activeTab === "logs" && <LogViewer connection={session.connection} />}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Terminal ── */
interface HistoryEntry { cmd: string; output: string; exitCode: number; }

function TerminalPanel({ connection }: { connection: SessionSummary["connection"] }) {
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [running, setRunning] = useState(false);
  const [historyIdx, setHistoryIdx] = useState(-1);
  const outputRef = useRef<HTMLDivElement>(null);

  const runCommand = async () => {
    if (!input.trim() || running) return;
    setRunning(true);
    const cmd = input;
    setInput(""); setHistoryIdx(-1);
    try {
      const result = await executeCommand(connection, cmd);
      setHistory((h) => [...h, { cmd, output: result.stdout + result.stderr, exitCode: result.exitCode }]);
    } catch (err) {
      setHistory((h) => [...h, { cmd, output: `Error: ${err}`, exitCode: -1 }]);
    }
    setRunning(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") { runCommand(); }
    else if (e.key === "ArrowUp") {
      e.preventDefault();
      const cmds = history.map((h) => h.cmd);
      if (!cmds.length) return;
      const newIdx = historyIdx === -1 ? cmds.length - 1 : Math.max(0, historyIdx - 1);
      setHistoryIdx(newIdx); setInput(cmds[newIdx]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const cmds = history.map((h) => h.cmd);
      if (historyIdx === -1) return;
      const newIdx = historyIdx + 1;
      if (newIdx >= cmds.length) { setHistoryIdx(-1); setInput(""); }
      else { setHistoryIdx(newIdx); setInput(cmds[newIdx]); }
    }
  };

  useEffect(() => { outputRef.current?.scrollTo(0, outputRef.current.scrollHeight); }, [history]);

  return (
    <div className="bg-[#0a0a0a] rounded-xl border border-gray-800/50 font-mono text-[13px] min-h-[420px] flex flex-col overflow-hidden">
      {/* Title bar */}
      <div className="flex items-center gap-2 px-4 py-2.5 bg-[#111] border-b border-gray-800/50">
        <div className="flex gap-1.5">
          <span className="w-3 h-3 rounded-full bg-red-500/80" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <span className="w-3 h-3 rounded-full bg-green-500/80" />
        </div>
        <span className="text-[11px] text-gray-500 ml-2">sandbox@microvm ~ </span>
      </div>
      {/* Output */}
      <div ref={outputRef} className="flex-1 overflow-y-auto p-4 space-y-3 max-h-[500px]">
        {history.length === 0 && !running && (
          <div className="text-gray-600 text-sm">Type a command and press Enter to execute in the sandbox.</div>
        )}
        {history.map((entry, i) => (
          <div key={i}>
            <div className="flex items-center gap-2">
              <span className="text-green-400 select-none">❯</span>
              <span className="text-green-300">{entry.cmd}</span>
            </div>
            <pre className="text-gray-400 whitespace-pre-wrap break-all pl-5 mt-0.5 leading-relaxed">{String(entry.output || "")}</pre>
            {entry.exitCode !== 0 && typeof entry.exitCode === "number" && !isNaN(entry.exitCode) && (
              <div className="text-red-400/70 text-xs pl-5 mt-0.5">exit {entry.exitCode}</div>
            )}
          </div>
        ))}
        {running && (
          <div className="text-blue-400 flex items-center gap-2 text-sm">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Executing...
          </div>
        )}
      </div>
      {/* Input */}
      <div className="flex items-center gap-2 px-4 py-3 bg-[#0d0d0d] border-t border-gray-800/50">
        <span className="text-green-400 select-none">❯</span>
        <input type="text" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={handleKeyDown}
          placeholder="Type a command..."
          className="flex-1 bg-transparent outline-none text-green-300 placeholder-gray-700 caret-green-400"
          disabled={running} autoFocus />
      </div>
    </div>
  );
}

/* ── Files ── */
interface FileEntry { name: string; kind: string; size: number; }

const QUICK_PATHS = [
  { label: "/tmp", path: "/tmp" },
  { label: "/mnt/workspace", path: "/mnt/workspace" },
  { label: "/home", path: "/home" },
  { label: "/", path: "/" },
];

function sanitizePath(p: string): string {
  return p.replace(/[;&|\`$(){}\\]/g, "");
}

function FilesPanel({ connection }: { connection: SessionSummary["connection"] }) {
  const [currentPath, setCurrentPath] = useState("/tmp");
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [viewingFile, setViewingFile] = useState<string | null>(null);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [loadingContent, setLoadingContent] = useState(false);

  const fetchFiles = useCallback((path: string) => {
    setLoadingFiles(true); setFileContent(null); setViewingFile(null);
    // Try protocol fs.list first, fall back to ls for paths outside /tmp
    listSandboxFiles(connection, path).then((data) => {
      if (Array.isArray(data) && data.length > 0) {
        setFiles(data); setLoadingFiles(false);
      } else {
        // Fallback: use ls via execute for any path
        executeCommand(connection, `ls -la ${sanitizePath(path)} 2>/dev/null`).then((r) => {
          if (r.exitCode !== 0) { setFiles([]); setLoadingFiles(false); return; }
          const entries: FileEntry[] = r.stdout.trim().split("\n").slice(1).filter(Boolean).map((line: string) => {
            const parts = line.split(/\s+/);
            const perms = parts[0] || "";
            const size = parseInt(parts[4] || "0") || 0;
            const name = parts.slice(8).join(" ");
            if (!name || name === "." || name === "..") return null;
            return { name, kind: perms.startsWith("d") ? "directory" : "file", size };
          }).filter(Boolean) as FileEntry[];
          setFiles(entries); setLoadingFiles(false);
        }).catch(() => { setFiles([]); setLoadingFiles(false); });
      }
    }).catch(() => {
      // Protocol failed entirely — use ls fallback
      executeCommand(connection, `ls -la ${sanitizePath(path)} 2>/dev/null`).then((r) => {
        if (r.exitCode !== 0) { setFiles([]); setLoadingFiles(false); return; }
        const entries: FileEntry[] = r.stdout.trim().split("\n").slice(1).filter(Boolean).map((line: string) => {
          const parts = line.split(/\s+/);
          const perms = parts[0] || "";
          const size = parseInt(parts[4] || "0") || 0;
          const name = parts.slice(8).join(" ");
          if (!name || name === "." || name === "..") return null;
          return { name, kind: perms.startsWith("d") ? "directory" : "file", size };
        }).filter(Boolean) as FileEntry[];
        setFiles(entries); setLoadingFiles(false);
      }).catch(() => { setFiles([]); setLoadingFiles(false); });
    });
  }, [connection]);

  useEffect(() => { fetchFiles(currentPath); }, [currentPath, fetchFiles]);

  const navigateTo = (name: string) => setCurrentPath(currentPath === "/" ? `/${name}` : `${currentPath}/${name}`);
  const navigateUp = () => { const p = currentPath.split("/").filter(Boolean); p.pop(); setCurrentPath(p.length ? "/" + p.join("/") : "/"); };
  const openFile = (name: string) => {
    const fp = currentPath === "/" ? `/${name}` : `${currentPath}/${name}`;
    setLoadingContent(true); setViewingFile(fp);
    // Try protocol first, fall back to cat for paths outside /tmp
    readSandboxFile(connection, fp).then((c) => { setFileContent(c); setLoadingContent(false); }).catch(() => {
      executeCommand(connection, `cat ${sanitizePath(fp)} 2>&1`).then((r) => {
        setFileContent(r.stdout || r.stderr || "(empty)"); setLoadingContent(false);
      }).catch((e) => { setFileContent(`Error: ${e}`); setLoadingContent(false); });
    });
  };
  const pathParts = currentPath.split("/").filter(Boolean);

  return (
    <div className="min-h-[400px]">
      {/* Quick nav */}
      <div className="flex items-center gap-2 mb-3">
        {QUICK_PATHS.map((qp) => (
          <button key={qp.path} onClick={() => setCurrentPath(qp.path)}
            className={cn(
              "text-xs px-2.5 py-1 rounded-lg border transition-colors",
              currentPath.startsWith(qp.path) && currentPath.length <= qp.path.length + 1
                ? "bg-[var(--accent)]/10 text-[var(--accent)] border-[var(--accent)]/20"
                : "bg-[var(--bg-tertiary)] text-[var(--text-muted)] border-[var(--border-primary)] hover:border-[var(--border-secondary)]"
            )}>
            {qp.label}
          </button>
        ))}
      </div>
      {/* Breadcrumb */}
      <div className="flex items-center gap-1 text-sm mb-4 text-[var(--text-muted)]">
        <button onClick={() => setCurrentPath("/")} className="hover:text-[var(--text-primary)] transition-colors">/</button>
        {pathParts.map((part, idx) => (
          <span key={idx} className="flex items-center gap-1">
            <ChevronRight className="w-3 h-3" />
            <button onClick={() => setCurrentPath("/" + pathParts.slice(0, idx + 1).join("/"))} className="hover:text-[var(--text-primary)] transition-colors">{part}</button>
          </span>
        ))}
        <button onClick={navigateUp} className="ml-auto p-1 rounded-lg hover:bg-[var(--bg-tertiary)] text-[var(--text-muted)]" title="Up"><ArrowUp className="w-4 h-4" /></button>
        <button onClick={() => fetchFiles(currentPath)} className="p-1 rounded-lg hover:bg-[var(--bg-tertiary)] text-[var(--text-muted)]" title="Refresh"><RefreshCcw className="w-4 h-4" /></button>
      </div>
      {viewingFile ? (
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-[var(--text-muted)] font-mono">{viewingFile}</span>
            <button onClick={() => { setViewingFile(null); setFileContent(null); }} className="text-xs text-blue-400 hover:text-blue-300 font-medium">Back</button>
          </div>
          <div className="bg-[#0a0a0a] rounded-xl p-4 font-mono text-sm text-gray-400 overflow-auto max-h-[400px] border border-gray-800/50">
            {loadingContent ? <div className="flex items-center gap-2 text-[var(--text-muted)]"><Loader2 className="w-4 h-4 animate-spin" /> Loading...</div> : <pre className="whitespace-pre-wrap break-all">{fileContent}</pre>}
          </div>
        </div>
      ) : loadingFiles ? (
        <div className="text-[var(--text-muted)] flex items-center gap-2 py-8 justify-center"><Loader2 className="w-4 h-4 animate-spin" /> Loading...</div>
      ) : (!files || !files.length) ? (
        <div className="text-[var(--text-muted)] text-sm py-8 text-center">Empty directory</div>
      ) : (
        <div className="divide-y divide-[var(--border-primary)]">
          {files.map((file) => (
            <button key={file.name} onClick={() => file.kind === "directory" ? navigateTo(file.name) : openFile(file.name)}
              className="flex items-center gap-3 w-full px-3 py-2.5 hover:bg-[var(--accent)]/5 text-left transition-colors group">
              {file.kind === "directory" ? <Folder className="w-4 h-4 text-blue-400 shrink-0" /> : <File className="w-4 h-4 text-[var(--text-muted)] shrink-0" />}
              <span className="text-sm font-mono text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] truncate">{file.name}</span>
              {file.kind !== "directory" && <span className="text-xs text-[var(--text-muted)] ml-auto">{formatSize(file.size)}</span>}
              {file.kind === "directory" && <ChevronRight className="w-3 h-3 text-[var(--text-muted)] ml-auto opacity-0 group-hover:opacity-100" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function formatSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-xl p-4">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{label}</p>
      <p className="text-sm font-mono mt-1.5 truncate text-[var(--text-secondary)]">{value}</p>
    </div>
  );
}
