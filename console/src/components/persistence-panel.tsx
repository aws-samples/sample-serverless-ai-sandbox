"use client";
import { useCallback, useEffect, useState } from "react";
import { executeCommand, type SessionSummary } from "@/lib/api";
import { cn } from "@/lib/utils";
import { HardDrive, RefreshCcw, CheckCircle, XCircle, Loader2 } from "lucide-react";

interface MountInfo {
  mounted: boolean;
  fsType: string;
  used: string;
  available: string;
  usedPct: number;
  fileCount: number;
}

export function PersistencePanel({ connection }: { connection: SessionSummary["connection"] }) {
  const [info, setInfo] = useState<MountInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const check = useCallback(async () => {
    if (!connection) return;
    setLoading(true);
    try {
      const [mountCheck, dfCheck, countCheck] = await Promise.all([
        executeCommand(connection, "mountpoint -q /mnt/workspace && echo MOUNTED || echo NOT_MOUNTED"),
        executeCommand(connection, "df -h /mnt/workspace 2>/dev/null | tail -1"),
        executeCommand(connection, "find /mnt/workspace -maxdepth 2 -type f 2>/dev/null | wc -l"),
      ]);

      const mounted = mountCheck.stdout.trim() === "MOUNTED";
      if (!mounted) {
        setInfo({ mounted: false, fsType: "", used: "", available: "", usedPct: 0, fileCount: 0 });
        return;
      }

      const dfParts = dfCheck.stdout.trim().split(/\s+/);
      const pct = parseInt(dfParts[4]?.replaceAll("%", "") || "0");
      const count = parseInt(countCheck.stdout.trim()) || 0;

      setInfo({
        mounted: true,
        fsType: "NFS 4.2 (S3 Files)",
        used: dfParts[2] || "?",
        available: dfParts[3] || "?",
        usedPct: pct,
        fileCount: count,
      });
    } catch {
      setInfo(null);
    } finally {
      setLoading(false);
    }
  }, [connection]);

  useEffect(() => {
    check();
  }, [check]);

  if (loading) {
    return (
      <div className="text-gray-600 text-sm flex items-center gap-2 py-4">
        <Loader2 className="w-4 h-4 animate-spin" /> Checking persistence...
      </div>
    );
  }

  if (!info) return null;

  return (
    <div className={cn(
      "rounded-xl border p-4",
      info.mounted ? "border-blue-700/50 bg-blue-950/20" : "border-gray-800 bg-gray-900"
    )}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <HardDrive className={cn("w-4 h-4", info.mounted ? "text-blue-400" : "text-gray-600")} />
          <span className="text-sm font-medium">Persistent Workspace</span>
          {info.mounted ? (
            <span className="flex items-center gap-1 text-xs text-green-400">
              <CheckCircle className="w-3 h-3" /> Mounted
            </span>
          ) : (
            <span className="flex items-center gap-1 text-xs text-gray-500">
              <XCircle className="w-3 h-3" /> Not mounted
            </span>
          )}
        </div>
        <button
          onClick={check}
          className="p-1 rounded hover:bg-gray-800 text-gray-500 hover:text-white"
        >
          <RefreshCcw className="w-3.5 h-3.5" />
        </button>
      </div>

      {info.mounted && (
        <div className="grid grid-cols-3 gap-4 text-xs">
          <div>
            <span className="text-gray-500">Type</span>
            <p className="text-gray-300 font-mono mt-0.5">{info.fsType}</p>
          </div>
          <div>
            <span className="text-gray-500">Usage</span>
            <p className="text-gray-300 font-mono mt-0.5">{info.used} / {info.available} ({info.usedPct}%)</p>
          </div>
          <div>
            <span className="text-gray-500">Files</span>
            <p className="text-gray-300 font-mono mt-0.5">{info.fileCount} files</p>
          </div>
        </div>
      )}

      {!info.mounted && (
        <p className="text-xs text-gray-600">
          This session was created without persistence. Use <code className="text-gray-400">persistence: true</code> to mount S3 Files at /mnt/workspace.
        </p>
      )}
    </div>
  );
}
