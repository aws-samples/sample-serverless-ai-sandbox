"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { executeCommand, type SessionSummary } from "@/lib/api";
import { cn } from "@/lib/utils";
import { RefreshCcw, Loader2, HardDrive, Cpu, MemoryStick, Activity } from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface MetricPoint {
  time: string;
  memUsedPct: number;
  load1: number;
  diskUsedPct: number;
}

function parseMemory(stdout: string): { usedPct: number; usedMB: number; totalMB: number } | null {
  const lines = stdout.trim().split("\n");
  const total = lines.find((l) => l.startsWith("MemTotal"))?.match(/(\d+)/);
  const avail = lines.find((l) => l.startsWith("MemAvailable"))?.match(/(\d+)/);
  if (!total || !avail) return null;
  const totalMB = parseInt(total[1]) / 1024;
  const availMB = parseInt(avail[1]) / 1024;
  const usedMB = totalMB - availMB;
  return { usedPct: (usedMB / totalMB) * 100, usedMB, totalMB };
}

function parseLoad(stdout: string): number | null {
  const parts = stdout.trim().split(/\s+/);
  return parts.length > 0 ? parseFloat(parts[0]) : null;
}

function parseDisk(stdout: string): { usedPct: number; used: string; total: string } | null {
  const parts = stdout.trim().split(/\s+/);
  if (parts.length < 5) return null;
  const pctStr = parts[4]?.replaceAll("%", "");
  return { usedPct: parseInt(pctStr) || 0, used: parts[2] || "?", total: parts[1] || "?" };
}

function MiniChart({ data, dataKey, color, label }: {
  data: MetricPoint[];
  dataKey: keyof MetricPoint;
  color: string;
  label: string;
}) {
  return (
    <div className="bg-gray-950 border border-gray-800 rounded-lg p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-500 uppercase">{label}</span>
        {data.length > 0 && (
          <span className="text-sm font-mono text-gray-300">
            {typeof data[data.length - 1][dataKey] === "number"
              ? `${(data[data.length - 1][dataKey] as number).toFixed(1)}${dataKey.includes("Pct") ? "%" : ""}`
              : "—"}
          </span>
        )}
      </div>
      <div className="h-20">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 2, right: 2, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id={`grad-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity={0.3} />
                <stop offset="100%" stopColor={color} stopOpacity={0.05} />
              </linearGradient>
            </defs>
            <XAxis dataKey="time" hide />
            <YAxis hide domain={dataKey.includes("Pct") ? [0, 100] : ["auto", "auto"]} />
            <Tooltip
              contentStyle={{ backgroundColor: "#111", border: "1px solid #333", borderRadius: 8, fontSize: 11 }}
              labelStyle={{ color: "#666" }}
            />
            <Area
              type="monotone"
              dataKey={dataKey}
              stroke={color}
              fill={`url(#grad-${dataKey})`}
              strokeWidth={1.5}
              dot={false}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export function MetricsPanel({ connection }: { connection: SessionSummary["connection"] }) {
  const [history, setHistory] = useState<MetricPoint[]>([]);
  const [polling, setPolling] = useState(true);
  const [lastValues, setLastValues] = useState<{
    mem: ReturnType<typeof parseMemory>;
    load: number | null;
    disk: ReturnType<typeof parseDisk>;
    uptime: string;
  }>({ mem: null, load: null, disk: null, uptime: "—" });
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  const collectMetrics = useCallback(async () => {
    if (!connection) return;
    try {
      const [memResult, loadResult, diskResult, uptimeResult] = await Promise.all([
        executeCommand(connection, "cat /proc/meminfo | head -5"),
        executeCommand(connection, "cat /proc/loadavg"),
        executeCommand(connection, "df -h /tmp 2>/dev/null | tail -1"),
        executeCommand(connection, "cat /proc/uptime"),
      ]);

      const mem = memResult.exitCode === 0 ? parseMemory(memResult.stdout) : null;
      const load = loadResult.exitCode === 0 ? parseLoad(loadResult.stdout) : null;
      const disk = diskResult.exitCode === 0 ? parseDisk(diskResult.stdout) : null;

      let uptime = "—";
      if (uptimeResult.exitCode === 0) {
        const secs = parseFloat(uptimeResult.stdout.trim().split(/\s+/)[0]);
        const h = Math.floor(secs / 3600);
        const m = Math.floor((secs % 3600) / 60);
        const s = Math.floor(secs % 60);
        uptime = h > 0 ? `${h}h ${m}m ${s}s` : `${m}m ${s}s`;
      }

      const now = new Date();
      const time = now.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
      const point: MetricPoint = {
        time,
        memUsedPct: mem?.usedPct ?? 0,
        load1: load ?? 0,
        diskUsedPct: disk?.usedPct ?? 0,
      };

      setHistory((h) => [...h.slice(-59), point]);
      setLastValues({ mem, load, disk, uptime });
    } catch {
      // connection lost
    }
  }, [connection]);

  useEffect(() => {
    collectMetrics();
    if (polling) {
      intervalRef.current = setInterval(collectMetrics, 5000);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [collectMetrics, polling]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-gray-400">Live Metrics</h3>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-gray-500 cursor-pointer">
            <input
              type="checkbox"
              checked={polling}
              onChange={(e) => setPolling(e.target.checked)}
              className="rounded"
            />
            Auto-refresh (5s)
          </label>
          <button
            onClick={collectMetrics}
            className="p-1 rounded hover:bg-gray-800 text-gray-500 hover:text-white"
          >
            <RefreshCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-3">
        <SummaryCard
          icon={<MemoryStick className="w-4 h-4" />}
          label="Memory"
          value={lastValues.mem ? `${lastValues.mem.usedMB.toFixed(0)} / ${lastValues.mem.totalMB.toFixed(0)} MB` : "—"}
          color={lastValues.mem && lastValues.mem.usedPct > 80 ? "text-red-400" : "text-green-400"}
        />
        <SummaryCard
          icon={<Cpu className="w-4 h-4" />}
          label="CPU Load"
          value={lastValues.load !== null ? lastValues.load.toFixed(2) : "—"}
          color={lastValues.load !== null && lastValues.load > 1 ? "text-yellow-400" : "text-green-400"}
        />
        <SummaryCard
          icon={<HardDrive className="w-4 h-4" />}
          label="Disk"
          value={lastValues.disk ? `${lastValues.disk.used} / ${lastValues.disk.total}` : "—"}
          color={lastValues.disk && lastValues.disk.usedPct > 80 ? "text-red-400" : "text-green-400"}
        />
        <SummaryCard
          icon={<Activity className="w-4 h-4" />}
          label="Uptime"
          value={lastValues.uptime}
          color="text-blue-400"
        />
      </div>

      {/* Charts */}
      {history.length === 0 ? (
        <div className="text-gray-600 text-sm text-center py-8 flex items-center justify-center gap-2">
          <Loader2 className="w-4 h-4 animate-spin" /> Collecting first data point...
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-3">
          <MiniChart data={history} dataKey="memUsedPct" color="#4ade80" label="Memory %" />
          <MiniChart data={history} dataKey="load1" color="#60a5fa" label="CPU Load (1m)" />
          <MiniChart data={history} dataKey="diskUsedPct" color="#f59e0b" label="Disk %" />
        </div>
      )}
    </div>
  );
}

function SummaryCard({ icon, label, value, color }: {
  icon: React.ReactNode;
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div className="bg-gray-950 border border-gray-800 rounded-lg p-3">
      <div className="flex items-center gap-2 text-gray-500 mb-1">
        {icon}
        <span className="text-xs uppercase">{label}</span>
      </div>
      <p className={cn("text-sm font-mono", color)}>{value}</p>
    </div>
  );
}
