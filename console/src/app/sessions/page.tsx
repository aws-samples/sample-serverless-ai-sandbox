"use client";
import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { listSessions, terminateSession, createSession, type SessionSummary } from "@/lib/api";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { RefreshCcw, Trash2, Eye, Plus, Loader2, Server, Clock, ChevronRight, Boxes } from "lucide-react";
import { useToast } from "@/components/toast";
import { CreateSessionDialog, type CreateSessionOpts } from "@/components/create-session-dialog";

const STATE_PRIORITY: Record<string, number> = {
  RUNNING: 0, STARTING: 1, PROVISIONING: 2, ORCHESTRATING: 3, SUSPENDED: 4, FAILED: 5, TERMINATED: 6,
};

function sortSessions(sessions: SessionSummary[]): SessionSummary[] {
  return [...sessions].sort((a, b) => {
    const pa = STATE_PRIORITY[a.lifecycleState] ?? 99;
    const pb = STATE_PRIORITY[b.lifecycleState] ?? 99;
    if (pa !== pb) return pa - pb;
    return (b.createdAt ?? 0) - (a.createdAt ?? 0);
  });
}

function timeAgo(epochMs?: number): string {
  if (!epochMs) return "";
  const diff = Date.now() - epochMs;
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function StatusDot({ state }: { state: string }) {
  const colors: Record<string, string> = {
    RUNNING: "bg-green-400", SUSPENDED: "bg-yellow-400", TERMINATED: "bg-gray-500",
    FAILED: "bg-red-400", ORCHESTRATING: "bg-blue-400", PROVISIONING: "bg-blue-400", STARTING: "bg-blue-400",
  };
  const isActive = ["RUNNING", "ORCHESTRATING", "PROVISIONING", "STARTING"].includes(state);
  return (
    <span className="relative flex h-2.5 w-2.5">
      {isActive && <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-40", colors[state])} />}
      <span className={cn("relative inline-flex rounded-full h-2.5 w-2.5", colors[state] || "bg-gray-400")} />
    </span>
  );
}

function SessionBadge({ state }: { state: string }) {
  const styles: Record<string, string> = {
    RUNNING: "bg-green-500/10 text-green-400 border-green-500/20",
    SUSPENDED: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    TERMINATED: "bg-gray-500/10 text-gray-400 border-gray-500/20",
    FAILED: "bg-red-500/10 text-red-400 border-red-500/20",
    ORCHESTRATING: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    PROVISIONING: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    STARTING: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  };
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border", styles[state] || "bg-gray-500/10 text-gray-400 border-gray-500/20")}>
      <StatusDot state={state} />
      {state}
    </span>
  );
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>("all");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [creating, setCreating] = useState(false);
  const router = useRouter();
  const { toast } = useToast();
  const [showCreate, setShowCreate] = useState(false);

  const handleCreate = async (opts?: CreateSessionOpts) => {
    setCreating(true);
    try {
      const session = await createSession(opts);
      toast(`Session created: ${session.sessionId.slice(0, 12)}...`, "success");
      router.push(`/sessions/${session.sessionId}`);
    } catch (err) {
      toast(`Failed to create session: ${err}`, "error");
      setCreating(false);
    }
  };

  const fetchSessions = useCallback(() => {
    setLoading(true);
    listSessions().then((data) => { setSessions(data.sessions || []); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { fetchSessions(); }, [fetchSessions]);
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchSessions, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchSessions]);

  const filtered = filter === "all" ? sessions : sessions.filter((s) => s.lifecycleState === filter);
  const sorted = sortSessions(filtered);

  const handleTerminate = async (sessionId: string) => {
    if (!window.confirm("Terminate this session?")) return; // eslint-disable-line no-restricted-globals -- developer tool, not end-user facing
    try {
      await terminateSession(sessionId);
      toast(`Session ${sessionId.slice(0, 12)}... terminated`, "success");
      fetchSessions();
    } catch (err) {
      toast(`Termination failed: ${err}`, "error");
    }
  };

  const counts: Record<string, number> = {};
  for (const s of sessions) counts[s.lifecycleState] = (counts[s.lifecycleState] || 0) + 1;

  const FILTERS = [
    { key: "all", label: "All", color: "blue" },
    { key: "RUNNING", label: "Running", color: "green" },
    { key: "SUSPENDED", label: "Suspended", color: "yellow" },
    { key: "TERMINATED", label: "Terminated", color: "gray" },
    { key: "FAILED", label: "Failed", color: "red" },
  ];

  return (
    <div className="max-w-6xl">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">Sessions</h1>
          <p className="text-[var(--text-muted)] text-sm mt-1">Manage sandbox sessions across tenants</p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-[var(--text-muted)] cursor-pointer">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} className="rounded" />
            Auto-refresh
          </label>
          <button onClick={fetchSessions} className="flex items-center gap-2 bg-[var(--bg-tertiary)] hover:bg-[var(--border-secondary)] text-[var(--text-secondary)] px-3 py-2 rounded-xl text-sm transition-colors">
            <RefreshCcw className="w-3.5 h-3.5" /> Refresh
          </button>
          <button onClick={() => setShowCreate(true)} disabled={creating}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-5 py-2.5 rounded-xl text-sm font-medium transition-all shadow-lg shadow-blue-600/20">
            {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            {creating ? "Creating..." : "New Session"}
          </button>
        </div>
      </div>

      {/* Filter pills */}
      <div className="flex gap-2 mb-5">
        {FILTERS.map((f) => {
          const count = f.key === "all" ? sessions.length : (counts[f.key] || 0);
          const active = filter === f.key;
          return (
            <button key={f.key} onClick={() => setFilter(f.key)}
              className={cn(
                "px-3.5 py-1.5 rounded-xl text-xs font-medium border transition-all flex items-center gap-2",
                active
                  ? `bg-${f.color}-500/15 text-${f.color}-400 border-${f.color}-500/30`
                  : "bg-[var(--bg-secondary)] text-[var(--text-muted)] border-[var(--border-primary)] hover:border-[var(--border-secondary)]"
              )}>
              {f.label}
              <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center",
                active ? `bg-${f.color}-500/20` : "bg-[var(--bg-tertiary)]"
              )}>{count}</span>
            </button>
          );
        })}
      </div>

      {/* Table */}
      <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-2xl overflow-hidden">
        {/* Header row */}
        <div className="grid grid-cols-12 gap-4 px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] border-b border-[var(--border-primary)]">
          <div className="col-span-4">Session</div>
          <div className="col-span-2">Status</div>
          <div className="col-span-2">Tenant</div>
          <div className="col-span-2">Created</div>
          <div className="col-span-2 text-right">Actions</div>
        </div>

        {loading ? (
          <div className="p-12 text-center">
            <Loader2 className="w-5 h-5 animate-spin inline mr-2 text-[var(--text-muted)]" />
            <span className="text-[var(--text-muted)] text-sm">Loading sessions...</span>
          </div>
        ) : sorted.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-12 h-12 rounded-2xl bg-[var(--bg-tertiary)] flex items-center justify-center mx-auto mb-3">
              <Boxes className="w-6 h-6 text-[var(--text-muted)]" />
            </div>
            <p className="text-[var(--text-muted)] text-sm">
              {filter === "all" ? "No sessions yet" : `No ${filter.toLowerCase()} sessions`}
            </p>
          </div>
        ) : (
          sorted.map((session, idx) => (
            <div key={session.sessionId}
              className={cn(
                "grid grid-cols-12 gap-4 items-center px-5 py-3.5 group transition-all duration-150 hover:bg-[var(--accent)]/5",
                idx < sorted.length - 1 && "border-b border-[var(--border-primary)]"
              )}>
              {/* Session ID */}
              <Link href={`/sessions/${session.sessionId}`} className="col-span-4 flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-[var(--bg-tertiary)] flex items-center justify-center text-[var(--text-muted)] group-hover:bg-[var(--accent)]/10 group-hover:text-[var(--accent)] transition-colors shrink-0">
                  <Server className="w-3.5 h-3.5" />
                </div>
                <span className="font-mono text-sm text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors truncate">
                  {session.sessionId}
                </span>
              </Link>
              {/* Status */}
              <div className="col-span-2">
                <SessionBadge state={session.lifecycleState} />
              </div>
              {/* Tenant */}
              <div className="col-span-2 text-sm text-[var(--text-muted)]">
                {session.tenantId || "operator"}
              </div>
              {/* Created */}
              <div className="col-span-2 flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
                <Clock className="w-3 h-3" />
                {timeAgo(session.createdAt)}
              </div>
              {/* Actions */}
              <div className="col-span-2 flex justify-end gap-1">
                <Link href={`/sessions/${session.sessionId}`}
                  className="p-2 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] transition-colors" title="View details">
                  <Eye className="w-4 h-4" />
                </Link>
                {!["TERMINATED", "FAILED"].includes(session.lifecycleState) && (
                  <button onClick={() => handleTerminate(session.sessionId)}
                    className="p-2 rounded-lg text-[var(--text-muted)] hover:text-red-400 hover:bg-red-500/10 transition-colors" title="Terminate">
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      <CreateSessionDialog open={showCreate} onClose={() => setShowCreate(false)} onSubmit={handleCreate} />
    </div>
  );
}
