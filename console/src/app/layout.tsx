import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";
import { ToastProvider } from "@/components/toast";
import { ThemeProvider } from "@/components/theme-provider";
import { CommandPalette } from "@/components/command-palette";

export const metadata: Metadata = {
  title: "AWS Serverless Agent Sandbox",
  description: "Console for managing sandbox sessions",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="min-h-screen flex">
        <ThemeProvider>
          <ToastProvider>
            <CommandPalette />
            <Sidebar />
            <main className="flex-1 lg:ml-64 p-4 sm:p-6 lg:p-8 pt-18 lg:pt-8">
              {children}
            </main>
          </ToastProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
