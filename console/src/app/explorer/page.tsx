"use client";
import { useEffect, useState, useRef, useCallback } from "react";
import {
  createSession,
  getSession,
  suspendSession,
  resumeSession,
  terminateSession,
  executeCommand,
  listSandboxFiles,
  apiRequest,
  type SessionSummary,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  Play,
  Pause,
  RotateCcw,
  Trash2,
  Send,
  Loader2,
  Terminal,
  FolderOpen,
  Activity,
  File,
  Folder,
  ChevronRight,
  Clock,
  Cpu,
  HardDrive,
  Shield,
  ArrowRight,
  Copy,
  Check,
  Plus,
  ChevronDown,
} from "lucide-react";

// ── Preset API calls for the explorer ──
interface Preset {
  label: string;
  method: string;
  path?: string;
  command?: string;
  body?: Record<string, unknown>;
  needsSession: boolean;
}
interface PresetGroup {
  group: string;
  items: Preset[];
}
const PRESETS: PresetGroup[] = [
  {
    group: "Session Lifecycle",
    items: [
      { label: "Create Session (ephemeral)", method: "POST", path: "/sessions", body: { maxDurationSeconds: 3600, idleSeconds: 300, suspendedSeconds: 600, autoResume: true }, needsSession: false },
      { label: "Get Session", method: "GET", path: "/sessions/{sessionId}", needsSession: true },
      { label: "List Sessions", method: "GET", path: "/sessions", needsSession: false },
      { label: "Suspend", method: "POST", path: "/sessions/{sessionId}/suspend", needsSession: true },
      { label: "Resume", method: "POST", path: "/sessions/{sessionId}/resume", needsSession: true },
      { label: "Terminate", method: "POST", path: "/sessions/{sessionId}/terminate", needsSession: true },
    ],
  },
  {
    group: "Sandbox Operations",
    items: [
      { label: "Execute: whoami", method: "EXEC", command: "whoami", needsSession: true },
      { label: "Execute: id", method: "EXEC", command: "id", needsSession: true },
      { label: "Execute: python3 --version", method: "EXEC", command: "python3 --version", needsSession: true },
      { label: "Execute: ls -la /tmp", method: "EXEC", command: "ls -la /tmp", needsSession: true },
      { label: "Execute: uname -a", method: "EXEC", command: "uname -a", needsSession: true },
      { label: "Execute: cat /etc/os-release", method: "EXEC", command: "cat /etc/os-release", needsSession: true },
      { label: "Execute: git --version", method: "EXEC", command: "git --version", needsSession: true },
      { label: "List files: /tmp", method: "FILES", path: "/tmp", needsSession: true },
    ],
  },
  {
    group: "Ephemeral Storage (/tmp)",
    items: [
      { label: "Write file", method: "EXEC", command: "echo 'Hello from sandbox!' > /tmp/demo.txt && echo 'File written'", needsSession: true },
      { label: "Read file back", method: "EXEC", command: "cat /tmp/demo.txt", needsSession: true },
      { label: "Git init + commit", method: "EXEC", command: "cd /tmp && git init myproject && cd myproject && echo '# Demo' > README.md && git add . && git config user.email 'demo@sandbox' && git config user.name 'Demo' && git commit -m 'initial' && git log --oneline", needsSession: true },
      { label: "Install package (pip)", method: "EXEC", command: "HOME=/tmp pip install --quiet --target /tmp/pylibs cowsay && PYTHONPATH=/tmp/pylibs python3 -c \"import cowsay; cowsay.cow('Sandbox works!')\"", needsSession: true },
      { label: "Verify state survived", method: "EXEC", command: "echo '--- File ---' && cat /tmp/demo.txt && echo '--- Git ---' && cd /tmp/myproject && git log --oneline && echo '--- Package ---' && PYTHONPATH=/tmp/pylibs python3 -c \"import cowsay; cowsay.cow('Still here!')\"", needsSession: true },
    ],
  },
  {
    group: "Persistent Storage (S3 Files)",
    items: [
      { label: "Create with persistence", method: "POST", path: "/sessions", body: { maxDurationSeconds: 3600, idleSeconds: 600, suspendedSeconds: 1800, autoResume: true, persistence: true }, needsSession: false },
      { label: "Create with affinity key", method: "POST", path: "/sessions", body: { maxDurationSeconds: 3600, persistence: true, affinityKey: "demo-project" }, needsSession: false },
      { label: "Check mount", method: "EXEC", command: "mountpoint /mnt/workspace && echo 'Mounted!' || echo 'Not mounted'", needsSession: true },
      { label: "List files: /mnt/workspace", method: "EXEC", command: "ls -la /mnt/workspace/", needsSession: true },
      { label: "Write to workspace", method: "EXEC", command: "echo 'Persistent data written at '$(date) > /mnt/workspace/demo.txt && cat /mnt/workspace/demo.txt", needsSession: true },
      { label: "Python I/O on workspace", method: "EXEC", command: "python3 -c \"import json; print(json.dumps({'project':'demo','items':[1,2,3]}, indent=2))\" > /mnt/workspace/data.json && echo 'Written:' && cat /mnt/workspace/data.json", needsSession: true },
    ],
  },
  {
    group: "Bedrock via Proxy",
    items: [
      { label: "Bedrock: Nova Micro (via proxy)", method: "EXEC", command: "python3 -c \"\nimport http.client, json, os, re\nraw = os.environ.get('http_proxy', '')\nm = re.match(r'http://([^:]+):(\\d+)', raw)\nif not m:\n    print(f'http_proxy not set or unrecognized: {raw}'); exit(1)\nproxy_host, proxy_port = m.group(1), int(m.group(2))\nregion = 'us-east-1'\nbedrock = f'bedrock-runtime.{region}.amazonaws.com'\nbody = json.dumps({'modelId':'amazon.nova-micro-v1:0','messages':[{'role':'user','content':[{'text':'Say hello in exactly 5 words'}]}],'inferenceConfig':{'maxTokens':64,'temperature':0.0}}).encode()\nconn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=30)\nconn.request('POST', f'http://{bedrock}/model/amazon.nova-micro-v1:0/converse', body=body, headers={'Host':bedrock,'Content-Type':'application/json','Accept':'application/json'})\nresp = conn.getresponse()\ndata = json.loads(resp.read())\nprint(data['output']['message']['content'][0]['text'])\n\"", needsSession: true },
    ],
  },
  {
    group: "Egress Control",
    items: [
      { label: "Allowed: curl pypi.org", method: "EXEC", command: "curl -s --max-time 10 https://pypi.org/simple/ 2>&1 | head -10 || echo 'Failed'", needsSession: true },
      { label: "Blocked: curl google.com", method: "EXEC", command: "curl -s --max-time 5 https://www.google.com 2>&1 || echo 'BLOCKED (as expected)'", needsSession: true },
      { label: "Blocked: direct Bedrock (expected)", method: "EXEC", command: "python3 -c \"import boto3; c=boto3.client('bedrock-runtime',region_name='us-east-1'); c.converse(modelId='amazon.nova-micro-v1:0',messages=[{'role':'user','content':[{'text':'hi'}]}])\" 2>&1 || echo '\nExpected: DenyBedrockDirect policy blocks direct Bedrock calls'", needsSession: true },
    ],
  },
];

interface LogEntry {
  id: number;
  timestamp: Date;
  type: "request" | "response" | "info" | "error";
  method?: string;
  path?: string;
  status?: number;
  body?: string;
  duration?: number;
}

export default function ExplorerPage() {
  const [session, setSession] = useState<SessionSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [customCmd, setCustomCmd] = useState("");
  const [files, setFiles] = useState<Array<{ name: string; kind: string; size: number }>>([]);
  const [filePath, setFilePath] = useState("/tmp");
  const [sessionAge, setSessionAge] = useState("");
  const [pollTimer, setPollTimer] = useState<NodeJS.Timeout | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const [reconnecting, setReconnecting] = useState(false);
  const [showPolicyEditor, setShowPolicyEditor] = useState(false);
  const [manualSessionId, setManualSessionId] = useState("");

  // Restore session from localStorage on mount
  useEffect(() => {
    const savedId = localStorage.getItem("explorer-session-id");
    if (savedId && !session) {
      setReconnecting(true);
      getSession(savedId)
        .then((sess) => {
          if (sess.lifecycleState === "RUNNING" && sess.connection) {
            setSession(sess);
            addLog({ type: "info", body: `Reconnected to session ${sess.sessionId.slice(0, 12)}...` });
            refreshFiles(sess);
            startPolling(sess.sessionId);
          } else if (sess.lifecycleState === "SUSPENDED") {
            setSession(sess);
            addLog({ type: "info", body: `Reconnected to SUSPENDED session ${sess.sessionId.slice(0, 12)}... — click Resume to continue` });
          } else {
            localStorage.removeItem("explorer-session-id");
            addLog({ type: "info", body: `Previous session ${savedId.slice(0, 12)}... is ${sess.lifecycleState}` });
          }
        })
        .catch(() => {
          localStorage.removeItem("explorer-session-id");
        })
        .finally(() => setReconnecting(false));
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Persist session ID
  useEffect(() => {
    if (session?.sessionId) {
      localStorage.setItem("explorer-session-id", session.sessionId);
    }
  }, [session?.sessionId]);
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>(
    Object.fromEntries(PRESETS.map(g => [g.group, true]))
  );

  const addLog = useCallback((entry: Omit<LogEntry, "id" | "timestamp">) => {
    const newEntry = { ...entry, id: Date.now() + Math.random(), timestamp: new Date() };
    setLog(l => [...l, newEntry]);
  }, []);

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [log]);

  // Session age timer
  useEffect(() => {
    if (!session?.lifecycleState || session.lifecycleState === "TERMINATED") return;
    const created = (session as unknown as Record<string, unknown>).createdAt as number | undefined;
    if (!created) return;
    const interval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - created) / 1000);
      const mins = Math.floor(elapsed / 60);
      const secs = elapsed % 60;
      const hrs = Math.floor(mins / 60);
      if (hrs > 0) setSessionAge(`${hrs}h ${mins % 60}m ${secs}s`);
      else if (mins > 0) setSessionAge(`${mins}m ${secs}s`);
      else setSessionAge(`${secs}s`);
    }, 1000);
    return () => clearInterval(interval);
  }, [session]);

  // Poll session state
  const startPolling = useCallback((sessionId: string) => {
    if (pollTimer) clearInterval(pollTimer);
    const timer = setInterval(async () => {
      try {
        const s = await getSession(sessionId);
        setSession(s);
        if (["TERMINATED", "FAILED"].includes(s.lifecycleState)) {
          clearInterval(timer);
        }
      } catch { /* ignore */ }
    }, 5000);
    setPollTimer(timer);
    return () => clearInterval(timer);
  }, [pollTimer]);

  // Refresh files when session is running
  const refreshFiles = useCallback(async (sess?: SessionSummary | null) => {
    const s = sess || session;
    if (!s?.connection) return;
    try {
      const f = await listSandboxFiles(s.connection, filePath);
      setFiles(f || []);
    } catch { setFiles([]); }
  }, [session, filePath]);

  // Execute a preset
  const runPreset = useCallback(async (preset: (typeof PRESETS)[number]["items"][number]) => {
    setLoading(true);
    const start = Date.now();

    try {
      if (preset.method === "EXEC") {
        if (!session?.connection) { addLog({ type: "error", body: "No active session" }); return; }
        addLog({ type: "request", method: "EXEC", path: preset.command ?? "", body: `$ ${preset.command}` });
        const result = await executeCommand(session.connection, preset.command ?? "");
        const duration = Date.now() - start;
        addLog({
          type: "response",
          status: result.exitCode === 0 ? 200 : 500,
          body: result.stdout || result.stderr || "(no output)",
          duration,
        });
        refreshFiles();
      } else if (preset.method === "FILES") {
        if (!session?.connection) { addLog({ type: "error", body: "No active session" }); return; }
        addLog({ type: "request", method: "GET", path: `files:${preset.path}` });
        const f = await listSandboxFiles(session.connection, preset.path!);
        setFiles(f || []);
        setFilePath(preset.path!);
        addLog({ type: "response", status: 200, body: JSON.stringify(f, null, 2), duration: Date.now() - start });
      } else if (preset.method === "POST" && preset.path === "/sessions" && preset.body) {
        addLog({ type: "request", method: "POST", path: "/sessions", body: JSON.stringify(preset.body, null, 2) });
        const created = await createSession(preset.body as { maxDurationSeconds?: number; idleSeconds?: number });
        addLog({ type: "response", status: 201, body: JSON.stringify(created, null, 2), duration: Date.now() - start });
        addLog({ type: "info", body: "Waiting for session to become RUNNING..." });

        let sess = created;
        for (let i = 0; i < 30; i++) {
          if (sess.lifecycleState === "RUNNING" && sess.connection) break;
          await new Promise(r => setTimeout(r, 3000));
          sess = await getSession(created.sessionId);
          addLog({ type: "info", body: `  State: ${sess.lifecycleState}` });
        }
        setSession(sess);
        startPolling(sess.sessionId);
        if (sess.connection) refreshFiles(sess);
        addLog({ type: "info", body: `Session ${sess.sessionId.slice(0, 12)}... is ${sess.lifecycleState}` });
      } else if (preset.label === "Suspend") {
        if (!session) { addLog({ type: "error", body: "No active session" }); return; }
        addLog({ type: "request", method: "POST", path: `/sessions/${session.sessionId}/suspend` });
        await suspendSession(session.sessionId);
        const updated = await getSession(session.sessionId);
        setSession(updated);
        addLog({ type: "response", status: 200, body: JSON.stringify({ lifecycleState: updated.lifecycleState }, null, 2), duration: Date.now() - start });
      } else if (preset.label === "Resume") {
        if (!session) { addLog({ type: "error", body: "No active session" }); return; }
        addLog({ type: "request", method: "POST", path: `/sessions/${session.sessionId}/resume` });
        await resumeSession(session.sessionId);
        addLog({ type: "info", body: "Waiting for RUNNING..." });
        let sess = await getSession(session.sessionId);
        for (let i = 0; i < 20; i++) {
          if (sess.lifecycleState === "RUNNING" && sess.connection) break;
          await new Promise(r => setTimeout(r, 3000));
          sess = await getSession(session.sessionId);
          addLog({ type: "info", body: `  State: ${sess.lifecycleState}` });
        }
        setSession(sess);
        if (sess.connection) refreshFiles(sess);
        addLog({ type: "response", status: 200, body: JSON.stringify({ lifecycleState: sess.lifecycleState }, null, 2), duration: Date.now() - start });
      } else if (preset.label === "Terminate") {
        if (!session) { addLog({ type: "error", body: "No active session" }); return; }
        addLog({ type: "request", method: "POST", path: `/sessions/${session.sessionId}/terminate` });
        await terminateSession(session.sessionId);
        const updated = await getSession(session.sessionId);
        setSession(updated);
        setFiles([]);
        if (pollTimer) clearInterval(pollTimer);
        addLog({ type: "response", status: 200, body: JSON.stringify({ lifecycleState: updated.lifecycleState }, null, 2), duration: Date.now() - start });
      } else if (preset.label === "Get Session") {
        if (!session) { addLog({ type: "error", body: "No active session" }); return; }
        addLog({ type: "request", method: "GET", path: `/sessions/${session.sessionId}` });
        const s = await getSession(session.sessionId);
        setSession(s);
        addLog({ type: "response", status: 200, body: JSON.stringify(s, null, 2), duration: Date.now() - start });
      } else if (preset.label === "List Sessions") {
        addLog({ type: "request", method: "GET", path: "/sessions" });
        const resp = await apiRequest("GET", "/sessions");
        const data = await resp.json();
        addLog({ type: "response", status: 200, body: JSON.stringify(data, null, 2), duration: Date.now() - start });
      }
    } catch (err) {
      addLog({ type: "error", body: `${err}` });
    } finally {
      setLoading(false);
    }
  }, [session, addLog, refreshFiles, startPolling, pollTimer]);

  const runCustomCommand = useCallback(async () => {
    if (!customCmd.trim() || !session?.connection) return;
    setLoading(true);
    const start = Date.now();
    addLog({ type: "request", method: "EXEC", path: customCmd, body: `$ ${customCmd}` });
    try {
      const result = await executeCommand(session.connection, customCmd);
      addLog({ type: "response", status: result.exitCode === 0 ? 200 : 500, body: result.stdout || result.stderr || "(no output)", duration: Date.now() - start });
      refreshFiles();
    } catch (err) {
      addLog({ type: "error", body: `${err}` });
    }
    setLoading(false);
    setCustomCmd("");
  }, [customCmd, session, addLog, refreshFiles]);

  const stateColor: Record<string, string> = {
    RUNNING: "bg-green-500",
    SUSPENDED: "bg-yellow-500",
    TERMINATED: "bg-gray-500",
    FAILED: "bg-red-500",
    ORCHESTRATING: "bg-blue-500",
    PROVISIONING: "bg-blue-500",
  };

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold">API Explorer</h1>
          <p className="text-gray-400 text-sm mt-1">
            Raw API calls with live session panel — no model in the loop
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* Connect to existing session */}
          <div className="flex gap-1">
            <input
              value={manualSessionId}
              onChange={e => setManualSessionId(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter" && manualSessionId.trim()) {
                setReconnecting(true);
                getSession(manualSessionId.trim()).then(s => {
                  setSession(s);
                  addLog({ type: "info", body: `Connected to ${s.sessionId.slice(0, 12)}... (${s.lifecycleState})` });
                  if (s.connection) { refreshFiles(s); startPolling(s.sessionId); }
                }).catch(e => addLog({ type: "error", body: `${e}` })).finally(() => setReconnecting(false));
              }}}
              placeholder="Session ID..."
              className="bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 text-xs font-mono w-48 focus:outline-none focus:border-blue-500"
            />
            <button
              onClick={() => {
                if (!manualSessionId.trim()) return;
                setReconnecting(true);
                getSession(manualSessionId.trim()).then(s => {
                  setSession(s);
                  addLog({ type: "info", body: `Connected to ${s.sessionId.slice(0, 12)}... (${s.lifecycleState})` });
                  if (s.connection) { refreshFiles(s); startPolling(s.sessionId); }
                }).catch(e => addLog({ type: "error", body: `${e}` })).finally(() => setReconnecting(false));
              }}
              disabled={reconnecting || !manualSessionId.trim()}
              className="bg-gray-800 hover:bg-gray-700 disabled:opacity-30 text-xs px-3 py-1.5 rounded-lg"
            >
              {reconnecting ? <Loader2 className="w-3 h-3 animate-spin" /> : "Connect"}
            </button>
          </div>
          <button
            onClick={() => setShowPolicyEditor(!showPolicyEditor)}
            className={cn("flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-colors",
              showPolicyEditor ? "bg-blue-600/20 text-blue-400 border-blue-700" : "bg-gray-800 text-gray-400 border-gray-700 hover:border-gray-600")}
          >
            <Shield className="w-3.5 h-3.5" /> Egress Policy
          </button>
          {session && (
            <button
              onClick={() => { setSession(null); setFiles([]); localStorage.removeItem("explorer-session-id"); addLog({ type: "info", body: "Session disconnected" }); }}
              className="p-1.5 rounded hover:bg-gray-800 text-gray-400"
              title="Disconnect session"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Egress Policy Editor */}
      {showPolicyEditor && <EgressPolicyEditor onLog={addLog} />}

      <div className="flex-1 flex gap-4 min-h-0">
        {/* Left: API Presets + Custom Command */}
        <div className="w-80 flex flex-col min-h-0">
          <div className="flex-1 overflow-y-auto space-y-1 pr-1">
            {PRESETS.map((group) => (
              <div key={group.group}>
                <button
                  onClick={() => setExpandedGroups(g => ({ ...g, [group.group]: !g[group.group] }))}
                  className="flex items-center gap-2 w-full text-left text-xs font-semibold text-gray-400 uppercase tracking-wider py-2 px-2 hover:text-gray-300"
                >
                  <ChevronDown className={cn("w-3 h-3 transition-transform", !expandedGroups[group.group] && "-rotate-90")} />
                  {group.group}
                </button>
                {expandedGroups[group.group] && group.items.map((preset, i) => {
                  const disabled = preset.needsSession && (!session || session.lifecycleState === "TERMINATED");
                  const isLifecycle = preset.method === "POST" || preset.method === "GET";
                  return (
                    <button
                      key={i}
                      onClick={() => !disabled && runPreset(preset)}
                      disabled={disabled || loading}
                      className={cn(
                        "w-full text-left text-sm px-3 py-2 rounded-lg transition-colors flex items-center gap-2",
                        disabled ? "opacity-30 cursor-not-allowed" : "hover:bg-gray-800 cursor-pointer",
                        loading && "opacity-50"
                      )}
                    >
                      <span className={cn(
                        "text-[10px] font-mono font-bold px-1.5 py-0.5 rounded shrink-0",
                        preset.method === "POST" ? "bg-blue-900/50 text-blue-400" :
                        preset.method === "GET" ? "bg-green-900/50 text-green-400" :
                        preset.method === "EXEC" ? "bg-purple-900/50 text-purple-400" :
                        "bg-gray-800 text-gray-400"
                      )}>
                        {preset.method === "EXEC" ? "CMD" : preset.method === "FILES" ? "LS" : preset.method}
                      </span>
                      <span className="truncate">{preset.label}</span>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>

          {/* Custom command input */}
          <div className="border-t border-gray-800 pt-3 mt-2">
            <label className="text-xs text-gray-500 mb-1 block">Custom command</label>
            <div className="flex gap-2">
              <input
                value={customCmd}
                onChange={e => setCustomCmd(e.target.value)}
                onKeyDown={e => e.key === "Enter" && runCustomCommand()}
                placeholder="e.g. python3 -c 'print(42)'"
                disabled={!session?.connection || loading}
                className="flex-1 bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500 disabled:opacity-30"
              />
              <button
                onClick={runCustomCommand}
                disabled={!session?.connection || loading || !customCmd.trim()}
                className="bg-purple-600 hover:bg-purple-700 disabled:opacity-30 text-white px-3 rounded-lg"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Center: Request/Response Log */}
        <div className="flex-1 flex flex-col min-h-0 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-950">
            <span className="text-xs font-semibold text-gray-400">Request / Response Log</span>
            <button onClick={() => setLog([])} className="text-xs text-gray-600 hover:text-gray-400">Clear</button>
          </div>
          <div ref={logRef} className="flex-1 overflow-y-auto p-3 space-y-2 font-mono text-xs">
            {log.length === 0 && (
              <div className="text-gray-600 text-center py-8">
                Click a preset on the left to start.<br />
                Begin with "Create Session" to provision a sandbox.
              </div>
            )}
            {log.map(entry => (
              <LogLine key={entry.id} entry={entry} />
            ))}
            {loading && (
              <div className="flex items-center gap-2 text-blue-400 py-1">
                <Loader2 className="w-3 h-3 animate-spin" /> Executing...
              </div>
            )}
          </div>
        </div>

        {/* Right: Session Panel */}
        <div className="w-72 flex flex-col min-h-0 space-y-3">
          {/* Session State Card */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Session</span>
              {session && (
                <div className="flex items-center gap-1.5">
                  <div className={cn("w-2 h-2 rounded-full", stateColor[session.lifecycleState] || "bg-gray-500", session.lifecycleState === "RUNNING" && "animate-pulse")} />
                  <span className="text-xs font-medium">{session.lifecycleState}</span>
                </div>
              )}
            </div>
            {session ? (
              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2 text-gray-400">
                  <Terminal className="w-3.5 h-3.5" />
                  <span className="font-mono truncate">{session.sessionId.slice(0, 20)}...</span>
                </div>
                <div className="flex items-center gap-2 text-gray-400">
                  <Clock className="w-3.5 h-3.5" />
                  <span>Uptime: {sessionAge || "—"}</span>
                </div>
                <div className="flex items-center gap-2 text-gray-400">
                  <Shield className="w-3.5 h-3.5" />
                  <span>Tenant: {session.tenantId || "operator"}</span>
                </div>
                <div className="flex items-center gap-2 text-gray-400">
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Max duration: 1h (3600s)</span>
                </div>
                {session.connection && (
                  <div className="flex items-center gap-2 text-gray-400">
                    <Activity className="w-3.5 h-3.5 text-green-400" />
                    <span className="text-green-400">Connected</span>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-gray-600">No active session. Click "Create Session" to start.</p>
            )}
          </div>

          {/* File Browser */}
          <div className="flex-1 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col min-h-0">
            <div className="flex items-center justify-between px-3 py-2 border-b border-gray-800">
              <div className="flex items-center gap-1.5">
                <FolderOpen className="w-3.5 h-3.5 text-gray-400" />
                <span className="text-xs font-semibold text-gray-400">Files</span>
              </div>
              <span className="text-[10px] font-mono text-gray-600">{filePath}</span>
            </div>
            <div className="flex-1 overflow-y-auto p-2 text-xs">
              {files.length === 0 ? (
                <p className="text-gray-600 text-center py-4">
                  {session?.connection ? "Empty or not loaded" : "No session"}
                </p>
              ) : (
                <div className="space-y-0.5">
                  {files.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 px-2 py-1 rounded hover:bg-gray-800">
                      {f.kind === "directory" ? (
                        <Folder className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                      ) : (
                        <File className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                      )}
                      <span className="truncate">{f.name}</span>
                      {f.kind === "file" && f.size > 0 && (
                        <span className="text-gray-600 ml-auto shrink-0">{f.size}B</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Quick Actions */}
          {session && session.lifecycleState !== "TERMINATED" && (
            <div className="flex gap-2">
              {session.lifecycleState === "RUNNING" && (
                <button
                  onClick={() => runPreset(PRESETS[0].items[3])}
                  disabled={loading}
                  className="flex-1 flex items-center justify-center gap-1.5 bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-400 border border-yellow-800 rounded-lg py-2 text-xs font-medium disabled:opacity-30"
                >
                  <Pause className="w-3.5 h-3.5" /> Suspend
                </button>
              )}
              {session.lifecycleState === "SUSPENDED" && (
                <button
                  onClick={() => runPreset(PRESETS[0].items[4])}
                  disabled={loading}
                  className="flex-1 flex items-center justify-center gap-1.5 bg-green-600/20 hover:bg-green-600/30 text-green-400 border border-green-800 rounded-lg py-2 text-xs font-medium disabled:opacity-30"
                >
                  <Play className="w-3.5 h-3.5" /> Resume
                </button>
              )}
              <button
                onClick={() => runPreset(PRESETS[0].items[5])}
                disabled={loading}
                className="flex items-center justify-center gap-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-800 rounded-lg py-2 px-3 text-xs font-medium disabled:opacity-30"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Log entry component ──
function LogLine({ entry }: { entry: LogEntry }) {
  const [copied, setCopied] = useState(false);
  const time = entry.timestamp.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

  const copy = () => {
    navigator.clipboard.writeText(entry.body || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  if (entry.type === "request") {
    return (
      <div className="text-blue-400">
        <span className="text-gray-600">{time}</span>{" "}
        <span className="font-bold">{entry.method}</span>{" "}
        <span>{entry.path}</span>
        {entry.body && entry.method !== "EXEC" && (
          <pre className="text-gray-500 ml-4 mt-1 whitespace-pre-wrap">{entry.body}</pre>
        )}
      </div>
    );
  }

  if (entry.type === "response") {
    const isOk = entry.status && entry.status < 400;
    return (
      <div className="group">
        <div className="flex items-center gap-2">
          <span className="text-gray-600">{time}</span>
          <span className={isOk ? "text-green-400" : "text-red-400"}>
            {isOk ? "✓" : "✗"} {entry.status}
          </span>
          {entry.duration && <span className="text-gray-600">{entry.duration}ms</span>}
          <button onClick={copy} className="opacity-0 group-hover:opacity-100 text-gray-600 hover:text-gray-400">
            {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
          </button>
        </div>
        {entry.body && (
          <pre className="text-gray-300 ml-4 mt-1 whitespace-pre-wrap max-h-[300px] overflow-auto bg-black/30 rounded p-2">
            {entry.body.length > 3000 ? entry.body.slice(0, 3000) + "\n... (truncated)" : entry.body}
          </pre>
        )}
      </div>
    );
  }

  if (entry.type === "error") {
    return (
      <div className="text-red-400">
        <span className="text-gray-600">{time}</span> ✗ {entry.body}
      </div>
    );
  }

  return (
    <div className="text-gray-500">
      <span className="text-gray-600">{time}</span> {entry.body}
    </div>
  );
}

// ── Egress Policy Editor ──
function EgressPolicyEditor({ onLog }: { onLog: (e: Omit<LogEntry, "id" | "timestamp">) => void }) {
  const [policy, setPolicy] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [newHost, setNewHost] = useState("");
  const [newNote, setNewNote] = useState("");
  const [saving, setSaving] = useState(false);

  const loadPolicy = useCallback(async () => {
    setLoading(true);
    try {
      const config = (await import("@/lib/api")).getConfig();
      const headers: Record<string, string> = {};
      if (config?.egressTable) headers["x-egress-table"] = config.egressTable;
      if (config?.region) headers["x-api-region"] = config.region;
      const resp = await fetch("/api/egress-policy", { headers });
      const data = await resp.json();
      setPolicy(data);
      onLog({ type: "info", body: `Egress policy loaded (v${data.policyVersion || "?"})` });
    } catch (err) {
      onLog({ type: "error", body: `Failed to load policy: ${err}` });
    }
    setLoading(false);
  }, [onLog]);

  useEffect(() => { loadPolicy(); }, [loadPolicy]);

  const savePolicy = async (updated: Record<string, unknown>) => {
    setSaving(true);
    try {
      const config = (await import("@/lib/api")).getConfig();
      const policyHeaders: Record<string, string> = { "Content-Type": "application/json" };
      if (config?.egressTable) policyHeaders["x-egress-table"] = config.egressTable;
      if (config?.region) policyHeaders["x-api-region"] = config.region;
      const resp = await fetch("/api/egress-policy", {
        method: "PUT",
        headers: policyHeaders,
        body: JSON.stringify(updated),
      });
      const result = await resp.json();
      if (result.ok) {
        setPolicy(updated);
        onLog({ type: "response", status: 200, body: `Policy saved (v${updated.policyVersion}). Proxy picks it up within 30s.` });
      } else {
        onLog({ type: "error", body: `Save failed: ${result.error}` });
      }
    } catch (err) {
      onLog({ type: "error", body: `Save failed: ${err}` });
    }
    setSaving(false);
  };

  const addDomain = () => {
    if (!newHost.trim() || !policy) return;
    const allowed = (policy.allowed as Array<{host: string; note: string}>) || [];
    if (allowed.some(e => e.host === newHost.trim())) return;
    const updated = {
      ...policy,
      policyVersion: ((policy.policyVersion as number) || 0) + 1,
      allowed: [...allowed, { host: newHost.trim(), note: newNote.trim() || "added via console" }],
    };
    savePolicy(updated);
    setNewHost("");
    setNewNote("");
  };

  const removeDomain = (host: string) => {
    if (!policy) return;
    const allowed = (policy.allowed as Array<{host: string; note: string}>) || [];
    const updated = {
      ...policy,
      policyVersion: ((policy.policyVersion as number) || 0) + 1,
      allowed: allowed.filter(e => e.host !== host),
    };
    savePolicy(updated);
  };

  if (loading || !policy) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-4">
        <div className="flex items-center gap-2 text-gray-400 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading egress policy...
        </div>
      </div>
    );
  }

  const bedrock = (policy.bedrock as {tier: number; hosts: string[]}) || { hosts: [] };
  const allowed = (policy.allowed as Array<{host: string; note: string}>) || [];

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-semibold">Egress Policy</span>
          <span className="text-[10px] bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">v{String(policy.policyVersion || 0)}</span>
          <span className="text-[10px] text-gray-600">Default: {String(policy.defaultAction || "deny")}</span>
        </div>
        <span className="text-[10px] text-gray-600">DynamoDB • 30s cache TTL • no rebuild needed</span>
      </div>

      {/* Bedrock hosts (read-only display) */}
      <div>
        <span className="text-xs text-gray-500 font-medium">Bedrock (Tier 1 — SigV4 re-signing)</span>
        <div className="flex flex-wrap gap-1 mt-1">
          {bedrock.hosts.map(h => (
            <span key={h} className="text-[10px] bg-green-900/30 text-green-400 border border-green-900 px-2 py-0.5 rounded font-mono">{h}</span>
          ))}
        </div>
      </div>

      {/* Other destination sets (packages, system, etc.) — read-only display */}
      {Object.entries(policy).map(([key, value]) => {
        if (key === "bedrock" || key === "allowed" || key === "policyVersion" || key === "defaultAction" || key === "tier2") return null;
        const group = value as { tier?: number; hosts?: string[]; note?: string };
        if (!group || !group.hosts || !Array.isArray(group.hosts) || group.hosts.length === 0) return null;
        return (
          <div key={key}>
            <span className="text-xs text-gray-500 font-medium capitalize">{key} (Tier {group.tier || 3} — CONNECT tunnel)</span>
            {group.note && <span className="text-[10px] text-gray-600 ml-2">{group.note}</span>}
            <div className="flex flex-wrap gap-1 mt-1">
              {group.hosts.map((h: string) => (
                <span key={h} className="text-[10px] bg-purple-900/30 text-purple-400 border border-purple-900 px-2 py-0.5 rounded font-mono">{h}</span>
              ))}
            </div>
          </div>
        );
      })}

      {/* Tier 2 aliases (token injection) — read-only display */}
      {Array.isArray(policy.tier2) && (policy.tier2 as Array<{alias: string; upstreamHost?: string}>).length > 0 && (
        <div>
          <span className="text-xs text-gray-500 font-medium">Tier 2 — Token Injection (aliased proxying)</span>
          <div className="space-y-1 mt-1">
            {(policy.tier2 as Array<{alias: string; upstreamHost?: string; injectHeader?: string}>).map((entry) => (
              <div key={entry.alias} className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-orange-400 bg-orange-900/20 border border-orange-900 px-2 py-0.5 rounded">{entry.alias}</span>
                {entry.upstreamHost && <span className="text-[10px] text-gray-500">→ {entry.upstreamHost}</span>}
                {entry.injectHeader && <span className="text-[10px] text-gray-600">({entry.injectHeader})</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Allowed destinations (editable) */}
      <div>
        <span className="text-xs text-gray-500 font-medium">Allowed Destinations (Tier 3 — CONNECT tunnel)</span>
        <div className="space-y-1 mt-1">
          {allowed.map(entry => (
            <div key={entry.host} className="flex items-center gap-2 group">
              <span className="text-xs font-mono text-gray-300 bg-gray-800 px-2 py-1 rounded flex-1">{entry.host}</span>
              <span className="text-[10px] text-gray-600 flex-1">{entry.note}</span>
              <button onClick={() => removeDomain(entry.host)} disabled={saving}
                className="opacity-0 group-hover:opacity-100 text-red-400 hover:text-red-300 text-xs px-1 disabled:opacity-30">✕</button>
            </div>
          ))}
          {allowed.length === 0 && <p className="text-xs text-gray-600">No allowed destinations — only Bedrock works.</p>}
        </div>
      </div>

      {/* Add new domain */}
      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="text-[10px] text-gray-600">Host</label>
          <input value={newHost} onChange={e => setNewHost(e.target.value)}
            onKeyDown={e => e.key === "Enter" && addDomain()}
            placeholder="e.g. cdn.amazonlinux.com"
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500" />
        </div>
        <div className="flex-1">
          <label className="text-[10px] text-gray-600">Note (optional)</label>
          <input value={newNote} onChange={e => setNewNote(e.target.value)}
            onKeyDown={e => e.key === "Enter" && addDomain()}
            placeholder="e.g. AL2023 package repos"
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500" />
        </div>
        <button onClick={addDomain} disabled={saving || !newHost.trim()}
          className="bg-blue-600 hover:bg-blue-700 disabled:opacity-30 text-white text-xs px-3 py-1 rounded font-medium flex items-center gap-1">
          {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Plus className="w-3 h-3" />} Add
        </button>
      </div>
    </div>
  );
}
