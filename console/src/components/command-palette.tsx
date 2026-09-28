"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  Boxes,
  Terminal,
  Code2,
  Settings,
  Plus,
  Search,
} from "lucide-react";

interface PaletteItem {
  id: string;
  label: string;
  icon: typeof LayoutDashboard;
  action: () => void;
  section: string;
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const items: PaletteItem[] = [
    { id: "nav-dashboard", label: "Go to Dashboard", icon: LayoutDashboard, action: () => router.push("/"), section: "Navigation" },
    { id: "nav-sessions", label: "Go to Sessions", icon: Boxes, action: () => router.push("/sessions"), section: "Navigation" },
    { id: "nav-playground", label: "Go to Playground", icon: Terminal, action: () => router.push("/playground"), section: "Navigation" },
    { id: "nav-explorer", label: "Go to API Explorer", icon: Code2, action: () => router.push("/explorer"), section: "Navigation" },
    { id: "nav-settings", label: "Go to Settings", icon: Settings, action: () => router.push("/settings"), section: "Navigation" },
    { id: "action-new-session", label: "Create new session", icon: Plus, action: () => router.push("/sessions"), section: "Actions" },
  ];

  const filtered = query.trim()
    ? items.filter((i) => i.label.toLowerCase().includes(query.toLowerCase()))
    : items;

  const execute = useCallback(
    (item: PaletteItem) => {
      setOpen(false);
      setQuery("");
      item.action();
    },
    []
  );

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((o) => !o);
        setQuery("");
        setSelectedIdx(0);
      }
      if (e.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  useEffect(() => {
    setSelectedIdx(0);
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIdx((i) => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" && filtered[selectedIdx]) {
      execute(filtered[selectedIdx]);
    }
  };

  if (!open) return null;

  const sections = [...new Set(filtered.map((i) => i.section))];

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[90]" onClick={() => setOpen(false)} />
      <div className="fixed top-[20%] left-1/2 -translate-x-1/2 w-full max-w-lg z-[91]">
        <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl overflow-hidden">
          <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-800">
            <Search className="w-4 h-4 text-gray-500" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a command or search..."
              className="flex-1 bg-transparent text-sm outline-none text-gray-200 placeholder-gray-600"
            />
            <kbd className="text-[10px] text-gray-600 bg-gray-800 px-1.5 py-0.5 rounded border border-gray-700">ESC</kbd>
          </div>
          <div className="max-h-80 overflow-y-auto py-2">
            {filtered.length === 0 && (
              <div className="text-sm text-gray-600 text-center py-6">No results</div>
            )}
            {sections.map((section) => (
              <div key={section}>
                <div className="px-4 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-600">
                  {section}
                </div>
                {filtered
                  .filter((i) => i.section === section)
                  .map((item) => {
                    const globalIdx = filtered.indexOf(item);
                    const Icon = item.icon;
                    return (
                      <button
                        key={item.id}
                        onClick={() => execute(item)}
                        onMouseEnter={() => setSelectedIdx(globalIdx)}
                        className={cn(
                          "flex items-center gap-3 w-full px-4 py-2 text-sm text-left transition-colors",
                          globalIdx === selectedIdx
                            ? "bg-blue-600/20 text-blue-300"
                            : "text-gray-400 hover:bg-gray-800"
                        )}
                      >
                        <Icon className="w-4 h-4 shrink-0" />
                        {item.label}
                      </button>
                    );
                  })}
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
