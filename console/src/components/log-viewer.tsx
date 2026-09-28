"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { executeCommand, type SessionSummary } from "@/lib/api";
import { cn } from "@/lib/utils";
import { RefreshCcw, Loader2, Trash2, Download } from "lucide-react";

interface LogLine {
  id: number;
  timestamp: string;
  content: string;
}

export function LogViewer({ connection }: { connection: SessionSummary["connection"] }) {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [loading, setLoading] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const [polling, setPolling] = useState(true);
  const [logSource, setLogSource] = useState("/tmp");
  const containerRef = useRef<HTMLDivElement>(null);
  const nextId = useRef(0);

  const fetchLogs = useCallback(async () => {
    if (!connection) return;
    try {
      // Check for common log locations
      const result = await executeCommand(
        connection,
        `find ${logSource} -maxdepth 2 -name "*.log" -o -name "*.txt" -o -name "stdout" -o -name "stderr" 2>/dev/null | head -5; echo "---SEPARATOR---"; ls -lt ${logSource}/*.log ${logSource}/*.txt 2>/dev/null | head -10; echo "---SEPARATOR---"; dmesg 2>/dev/null | tail -30 || journalctl -n 30 --no-pager 2>/dev/null || tail -30 /var/log/messages 2>/dev/null || echo "No system logs available"`
      );

      const parts = result.stdout.split("---SEPARATOR---");
      const systemLogs = (parts[2] || "").trim();

      if (systemLogs && systemLogs !== "No system logs available") {
        const newLines = systemLogs.split("\n").filter(Boolean).map((line) => ({
          id: nextId.current++,
          timestamp: new Date().toLocaleTimeString("en-US", { hour12: false }),
          content: line,
        }));
        setLines((prev) => {
          const combined = [...prev, ...newLines];
          return combined.slice(-500); // Keep last 500 lines
        });
      }
    } catch {
      // connection lost
    } finally {
      setLoading(false);
    }
  }, [connection, logSource]);

  useEffect(() => {
    fetchLogs();
    if (polling) {
      const timer = setInterval(fetchLogs, 10000);
      return () => clearInterval(timer);
    }
  }, [fetchLogs, polling]);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [lines, autoScroll]);

  const exportLogs = () => {
    const content = lines.map((l) => `[${l.timestamp}] ${l.content}`).join("\n");
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sandbox-logs-${new Date().toISOString().slice(0, 19)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-gray-400">System Logs</h3>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-gray-500 cursor-pointer">
            <input
              type="checkbox"
              checked={polling}
              onChange={(e) => setPolling(e.target.checked)}
              className="rounded"
            />
            Auto-refresh
          </label>
          <label className="flex items-center gap-1.5 text-xs text-gray-500 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded"
            />
            Auto-scroll
          </label>
          <button onClick={exportLogs} className="p-1 rounded hover:bg-gray-800 text-gray-500" title="Export logs">
            <Download className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => setLines([])} className="p-1 rounded hover:bg-gray-800 text-gray-500" title="Clear">
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          <button onClick={fetchLogs} className="p-1 rounded hover:bg-gray-800 text-gray-500" title="Refresh">
            <RefreshCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div
        ref={containerRef}
        className="bg-black rounded-lg p-3 font-mono text-xs min-h-[400px] max-h-[500px] overflow-y-auto"
      >
        {loading && lines.length === 0 ? (
          <div className="text-gray-600 flex items-center gap-2 py-8 justify-center">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading logs...
          </div>
        ) : lines.length === 0 ? (
          <div className="text-gray-600 text-center py-8">
            No logs available. Logs appear here as the sandbox produces output.
          </div>
        ) : (
          lines.map((line) => (
            <div key={line.id} className="flex gap-2 py-0.5 hover:bg-gray-900/50">
              <span className="text-gray-600 shrink-0 select-none">{line.timestamp}</span>
              <span className={cn(
                "text-gray-400 break-all",
                line.content.toLowerCase().includes("error") && "text-red-400",
                line.content.toLowerCase().includes("warn") && "text-yellow-400",
              )}>
                {line.content}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
