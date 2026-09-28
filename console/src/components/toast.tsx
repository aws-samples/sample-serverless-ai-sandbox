"use client";
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { CheckCircle, XCircle, AlertTriangle, Info, X } from "lucide-react";

type ToastType = "success" | "error" | "warning" | "info";

interface Toast {
  id: string;
  message: string;
  type: ToastType;
}

interface ToastContextValue {
  toast: (message: string, type?: ToastType) => void;
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} });

export function useToast() {
  return useContext(ToastContext);
}

const ICONS: Record<ToastType, typeof CheckCircle> = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
};

const STYLES: Record<ToastType, string> = {
  success: "bg-green-900/90 border-green-700 text-green-200",
  error: "bg-red-900/90 border-red-700 text-red-200",
  warning: "bg-yellow-900/90 border-yellow-700 text-yellow-200",
  info: "bg-blue-900/90 border-blue-700 text-blue-200",
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((message: string, type: ToastType = "info") => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((t) => [...t, { id, message, type }]);
    setTimeout(() => {
      setToasts((t) => t.filter((item) => item.id !== id));
    }, 4000);
  }, []);

  const dismiss = useCallback((id: string) => {
    setToasts((t) => t.filter((item) => item.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-[100] space-y-2 max-w-sm">
        {toasts.map((t) => {
          const Icon = ICONS[t.type];
          return (
            <div
              key={t.id}
              className={cn(
                "flex items-start gap-2 border rounded-lg px-4 py-3 shadow-lg backdrop-blur-sm animate-in slide-in-from-right-5 fade-in-0 duration-200",
                STYLES[t.type]
              )}
            >
              <Icon className="w-4 h-4 mt-0.5 shrink-0" />
              <span className="text-sm flex-1">{t.message}</span>
              <button
                onClick={() => dismiss(t.id)}
                className="shrink-0 p-0.5 rounded hover:bg-white/10"
              >
                <X className="w-3 h-3" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
