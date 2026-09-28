"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useEffect, useState } from "react";
import { useTheme } from "@/components/theme-provider";
import {
  LayoutDashboard,
  Boxes,
  Terminal,
  Code2,
  Settings,
  Activity,
  Menu,
  X,
  Sun,
  Moon,
  Search,
} from "lucide-react";

const navItems = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/sessions", label: "Sessions", icon: Boxes },
  { href: "/playground", label: "Playground", icon: Terminal },
  { href: "/explorer", label: "API Explorer", icon: Code2 },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isMac, setIsMac] = useState(false);

  useEffect(() => {
    setIsMac(/Mac/.test(navigator.userAgent));
  }, []);
  const { theme, toggleTheme } = useTheme();

  return (
    <>
      {/* Mobile top bar */}
      <div className="lg:hidden fixed top-0 left-0 right-0 h-14 bg-[var(--bg-secondary)] border-b border-[var(--border-primary)] flex items-center px-4 z-50">
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="p-2 rounded-lg hover:bg-[var(--bg-tertiary)] text-[var(--text-muted)]"
        >
          {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
        <h1 className="text-sm font-bold text-[var(--text-primary)] ml-3">Agent Sandbox</h1>
      </div>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="lg:hidden fixed inset-0 bg-black/50 z-40"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed left-0 top-0 h-screen w-64 bg-[var(--bg-secondary)] border-r border-[var(--border-primary)] flex flex-col z-50 transition-transform duration-200",
          "lg:translate-x-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        )}
      >
        <div className="p-6 border-b border-[var(--border-primary)]">
          <h1 className="text-lg font-bold text-[var(--text-primary)]">Agent Sandbox</h1>
          <p className="text-xs text-[var(--text-muted)] mt-1">Visual Control Plane</p>
        </div>

        {/* Cmd+K hint */}
        <div className="px-4 pt-3 pb-1">
          <button
            onClick={() => {
              window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true }));
            }}
            className="flex items-center gap-2 w-full px-3 py-2 rounded-lg bg-[var(--bg-tertiary)]/50 border border-[var(--border-secondary)]/50 text-[var(--text-muted)] text-sm hover:bg-[var(--bg-tertiary)] hover:text-[var(--text-secondary)] transition-colors"
          >
            <Search className="w-3.5 h-3.5" />
            <span className="flex-1 text-left">Search...</span>
            <kbd className="text-[10px] bg-[var(--bg-tertiary)] px-1.5 py-0.5 rounded border border-[var(--border-secondary)]">
              {isMac ? "⌘K" : "Ctrl+K"}
            </kbd>
          </button>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active =
              pathname === item.href ||
              (item.href !== "/" && pathname.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors",
                  active
                    ? "bg-blue-600/20 text-blue-400"
                    : "text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]"
                )}
              >
                <Icon className="w-4 h-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="p-4 border-t border-[var(--border-primary)] space-y-3">
          <button
            onClick={toggleTheme}
            className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] transition-colors"
          >
            {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
          <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
            <Activity className="w-3 h-3" />
            <span>Connected</span>
          </div>
        </div>
      </aside>
    </>
  );
}
