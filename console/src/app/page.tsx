"use client";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { listSessions, createSession, type SessionSummary } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Boxes, Pause, PlayCircle, XCircle, Plus, Zap, Loader2, Clock, ChevronRight, Server } from "lucide-react";
import Link from "next/link";
import { useToast } from "@/components/toast";
import { CreateSessionDialog, type CreateSessionOpts } from "@/components/create-session-dialog";

const STATE_PRIORITY: Record<string, number> = {
  RUNNING: 0,
  STARTING: 1,
  PROVISIONING: 2,
  ORCHESTRATING: 3,
  SUSPENDED: 4,
  FAILED: 5,
  TERMINATED: 6,
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

/* ── Animated counter ── */
function AnimatedNumber({ value, duration = 600 }: { value: number; duration?: number }) {
  const [display, setDisplay] = useState(0);
  const rafRef = useRef<number>(0);

  useEffect(() => {
    const start = display;
    const diff = value - start;
    if (diff === 0) return;
    const t0 = performance.now();
    const step = (now: number) => {
      const elapsed = now - t0;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      setDisplay(Math.round(start + diff * eased));
      if (progress < 1) rafRef.current = requestAnimationFrame(step);
    };
    rafRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(rafRef.current);
  }, [value, duration]); // eslint-disable-line react-hooks/exhaustive-deps

  return <>{display}</>;
}

/* ── Stat card with gradient accent ── */
function StatCard({
  title,
  value,
  icon: Icon,
  gradient,
  iconColor,
  loading,
}: {
  title: string;
  value: number;
  icon: React.ElementType;
  gradient: string;
  iconColor: string;
  loading: boolean;
}) {
  return (
    <div className="relative overflow-hidden bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-2xl p-5 group hover:border-[var(--border-secondary)] transition-all duration-200">
      {/* Subtle gradient glow */}
      <div className={cn("absolute -top-12 -right-12 w-32 h-32 rounded-full opacity-20 blur-2xl group-hover:opacity-30 transition-opacity", gradient)} />
      <div className="relative flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">{title}</p>
          <p className="text-3xl font-bold mt-2 tabular-nums text-[var(--text-primary)]">
            {loading ? <span className="text-[var(--text-muted)]">&mdash;</span> : <AnimatedNumber value={value} />}
          </p>
        </div>
        <div className={cn("p-3 rounded-xl", iconColor)}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
}

/* ── Status dot with pulse ── */
function StatusDot({ state }: { state: string }) {
  const colors: Record<string, string> = {
    RUNNING: "bg-green-400",
    SUSPENDED: "bg-yellow-400",
    TERMINATED: "bg-gray-500",
    FAILED: "bg-red-400",
    ORCHESTRATING: "bg-blue-400",
    PROVISIONING: "bg-blue-400",
    STARTING: "bg-blue-400",
  };
  const isActive = ["RUNNING", "ORCHESTRATING", "PROVISIONING", "STARTING"].includes(state);

  return (
    <span className="relative flex h-2.5 w-2.5">
      {isActive && (
        <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-40", colors[state] || "bg-gray-400")} />
      )}
      <span className={cn("relative inline-flex rounded-full h-2.5 w-2.5", colors[state] || "bg-gray-400")} />
    </span>
  );
}

/* ── Session badge ── */
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
    <span className={cn(
      "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border",
      styles[state] || "bg-gray-500/10 text-gray-400 border-gray-500/20"
    )}>
      <StatusDot state={state} />
      {state}
    </span>
  );
}

/* ── Main dashboard ── */
export default function DashboardPage() {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
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

  useEffect(() => {
    listSessions()
      .then((data) => {
        setSessions(data.sessions || []);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  const running = sessions.filter((s) => s.lifecycleState === "RUNNING").length;
  const suspended = sessions.filter((s) => s.lifecycleState === "SUSPENDED").length;
  const terminated = sessions.filter((s) => ["TERMINATED", "FAILED"].includes(s.lifecycleState)).length;
  const total = sessions.length;
  const sorted = sortSessions(sessions);

  return (
    <div className="max-w-6xl">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">Dashboard</h1>
          <p className="text-[var(--text-muted)] text-sm mt-1">AWS Serverless Agent Sandbox overview</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => setShowCreate(true)}
            disabled={creating}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-5 py-2.5 rounded-xl text-sm font-medium transition-all shadow-lg shadow-blue-600/20 hover:shadow-blue-500/30"
          >
            {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            {creating ? "Creating..." : "New Session"}
          </button>
          <Link
            href="/playground"
            className="flex items-center gap-2 bg-[var(--bg-tertiary)] hover:bg-[var(--border-secondary)] text-[var(--text-secondary)] px-5 py-2.5 rounded-xl text-sm font-medium transition-all"
          >
            <Zap className="w-4 h-4" />
            Playground
          </Link>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 mb-6">
          <p className="text-red-400 text-sm">
            {error.includes("Not configured") ? (
              <>Not configured. <Link href="/settings" className="underline font-medium">Set up your API connection</Link></>
            ) : error}
          </p>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard title="Total Sessions" value={total} icon={Boxes} gradient="bg-blue-500" iconColor="bg-blue-500/10 text-blue-400" loading={loading} />
        <StatCard title="Running" value={running} icon={PlayCircle} gradient="bg-green-500" iconColor="bg-green-500/10 text-green-400" loading={loading} />
        <StatCard title="Suspended" value={suspended} icon={Pause} gradient="bg-yellow-500" iconColor="bg-yellow-500/10 text-yellow-400" loading={loading} />
        <StatCard title="Terminated" value={terminated} icon={XCircle} gradient="bg-red-500" iconColor="bg-red-500/10 text-red-400" loading={loading} />
      </div>

      {/* Recent sessions table */}
      <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-2xl overflow-hidden">
        <div className="px-5 py-4 border-b border-[var(--border-primary)] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-[var(--text-muted)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Recent Sessions</h2>
            {!loading && (
              <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-[var(--bg-tertiary)] text-[var(--text-muted)]">
                {total}
              </span>
            )}
          </div>
          <Link href="/sessions" className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors">
            View all <ChevronRight className="w-3 h-3" />
          </Link>
        </div>

        {loading ? (
          <div className="p-12 text-center">
            <Loader2 className="w-5 h-5 animate-spin inline mr-2 text-[var(--text-muted)]" />
            <span className="text-[var(--text-muted)] text-sm">Loading sessions...</span>
          </div>
        ) : sessions.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-12 h-12 rounded-2xl bg-[var(--bg-tertiary)] flex items-center justify-center mx-auto mb-3">
              <Boxes className="w-6 h-6 text-[var(--text-muted)]" />
            </div>
            <p className="text-[var(--text-muted)] text-sm mb-3">No sessions yet</p>
            <button
              onClick={() => setShowCreate(true)}
              disabled={creating}
              className="text-blue-400 hover:text-blue-300 text-sm font-medium"
            >
              Create your first session →
            </button>
          </div>
        ) : (
          <div>
            {/* Table header */}
            <div className="grid grid-cols-12 gap-4 px-5 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] border-b border-[var(--border-primary)]">
              <div className="col-span-5">Session</div>
              <div className="col-span-2">Status</div>
              <div className="col-span-2">Tenant</div>
              <div className="col-span-2">Created</div>
              <div className="col-span-1"></div>
            </div>
            {/* Rows */}
            {sorted.slice(0, 10).map((session, idx) => (
              <Link
                key={session.sessionId}
                href={`/sessions/${session.sessionId}`}
                className={cn(
                  "grid grid-cols-12 gap-4 items-center px-5 py-3.5 transition-all duration-150 group",
                  "hover:bg-[var(--accent)]/5",
                  idx < sorted.slice(0, 10).length - 1 && "border-b border-[var(--border-primary)]"
                )}
              >
                <div className="col-span-5 flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-[var(--bg-tertiary)] flex items-center justify-center text-[var(--text-muted)] group-hover:bg-[var(--accent)]/10 group-hover:text-[var(--accent)] transition-colors">
                    <Server className="w-3.5 h-3.5" />
                  </div>
                  <span className="font-mono text-sm text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors">
                    {session.sessionId.slice(0, 20)}
                  </span>
                </div>
                <div className="col-span-2">
                  <SessionBadge state={session.lifecycleState} />
                </div>
                <div className="col-span-2 text-sm text-[var(--text-muted)]">
                  {session.tenantId || "operator"}
                </div>
                <div className="col-span-2 flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
                  <Clock className="w-3 h-3" />
                  {timeAgo(session.createdAt)}
                </div>
                <div className="col-span-1 flex justify-end">
                  <ChevronRight className="w-4 h-4 text-[var(--text-muted)] opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>

      <CreateSessionDialog open={showCreate} onClose={() => setShowCreate(false)} onSubmit={handleCreate} />
    </div>
  );
}
