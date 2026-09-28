"use client";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { X, Loader2, HardDrive } from "lucide-react";

interface CreateSessionDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (opts: CreateSessionOpts) => Promise<void>;
}

export interface CreateSessionOpts {
  maxDurationSeconds: number;
  idleSeconds: number;
  suspendedSeconds: number;
  autoResume: boolean;
  persistence: boolean;
  affinityKey: string;
}

const DURATION_PRESETS = [
  { label: "30 min", value: 1800 },
  { label: "1 hour", value: 3600 },
  { label: "2 hours", value: 7200 },
  { label: "4 hours", value: 14400 },
];

const MEMORY_PRESETS = [
  { label: "512 MB", value: 512 },
  { label: "1 GB", value: 1024 },
  { label: "2 GB", value: 2048 },
];

export function CreateSessionDialog({ open, onClose, onSubmit }: CreateSessionDialogProps) {
  const [maxDuration, setMaxDuration] = useState(3600);
  const [idleSeconds, setIdleSeconds] = useState(300);
  const [suspendedSeconds, setSuspendedSeconds] = useState(600);
  const [autoResume, setAutoResume] = useState(true);
  const [persistence, setPersistence] = useState(false);
  const [affinityKey, setAffinityKey] = useState("");
  const [submitting, setSubmitting] = useState(false);

  if (!open) return null;

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      await onSubmit({
        maxDurationSeconds: maxDuration,
        idleSeconds,
        suspendedSeconds,
        autoResume,
        persistence,
        affinityKey: affinityKey.trim(),
      });
      onClose();
    } catch {
      // error handled by caller
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[80]" onClick={onClose} />
      <div className="fixed top-[15%] left-1/2 -translate-x-1/2 w-full max-w-md z-[81]">
        <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl">
          <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
            <h2 className="text-lg font-semibold">Create Session</h2>
            <button onClick={onClose} className="p-1 rounded hover:bg-gray-800 text-gray-400">
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="p-5 space-y-5">
            {/* Max Duration */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Max Duration</label>
              <div className="flex gap-2">
                {DURATION_PRESETS.map((p) => (
                  <button
                    key={p.value}
                    onClick={() => setMaxDuration(p.value)}
                    className={cn(
                      "flex-1 text-xs py-2 rounded-lg border transition-colors",
                      maxDuration === p.value
                        ? "bg-blue-600/20 border-blue-600 text-blue-400"
                        : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600"
                    )}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Idle timeout */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Idle timeout (seconds)</label>
              <input
                type="number"
                value={idleSeconds}
                onChange={(e) => setIdleSeconds(parseInt(e.target.value) || 300)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
              />
              <p className="text-xs text-gray-600 mt-1">Suspend after this many seconds of no activity</p>
            </div>

            {/* Auto resume */}
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={autoResume}
                onChange={(e) => setAutoResume(e.target.checked)}
                className="rounded border-gray-600"
              />
              <div>
                <span className="text-sm text-gray-300">Auto-resume on reconnect</span>
                <p className="text-xs text-gray-600">Automatically resume suspended sessions</p>
              </div>
            </label>

            {/* Persistence */}
            <div className={cn(
              "rounded-lg border p-4 transition-colors",
              persistence ? "border-blue-600 bg-blue-600/10" : "border-gray-700 bg-gray-800/50"
            )}>
              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={persistence}
                  onChange={(e) => setPersistence(e.target.checked)}
                  className="rounded border-gray-600 mt-0.5"
                />
                <div>
                  <div className="flex items-center gap-2">
                    <HardDrive className="w-4 h-4 text-blue-400" />
                    <span className="text-sm font-medium text-gray-200">Persistent workspace</span>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Mount S3 Files at /mnt/workspace. Files survive suspend, resume, and termination.
                  </p>
                </div>
              </label>

              {persistence && (
                <div className="mt-3 ml-6">
                  <label className="block text-xs text-gray-400 mb-1">Affinity key (optional)</label>
                  <input
                    type="text"
                    value={affinityKey}
                    onChange={(e) => setAffinityKey(e.target.value)}
                    placeholder="e.g. my-project"
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-blue-500"
                  />
                  <p className="text-xs text-gray-600 mt-1">
                    Sessions with the same key share the same workspace files
                  </p>
                </div>
              )}
            </div>
          </div>

          <div className="flex justify-end gap-3 px-5 py-4 border-t border-gray-800">
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={submitting}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-5 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              {submitting ? "Creating..." : "Create Session"}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
