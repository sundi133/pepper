"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  MessageSquare,
  X,
  Send,
  Loader2,
  Bot,
  User,
  ChevronDown,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

type Role = "user" | "assistant";

interface Message {
  id: string;
  role: Role;
  content: string;
  streaming?: boolean;
}

const SUGGESTIONS = [
  "Summarise the critical findings",
  "Which findings should I fix first?",
  "Are any of these in authentication code?",
  "Show findings that affect user data",
  "What are the top 3 highest-risk issues?",
  "Are there any secrets exposed?",
];

// ─── Component ────────────────────────────────────────────────────────────────

export function ScanTriageChat({ scanId }: { scanId: string }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Focus textarea when panel opens
  useEffect(() => {
    if (open) {
      setTimeout(() => textareaRef.current?.focus(), 50);
    }
  }, [open]);

  const sendMessage = useCallback(
    async (text: string) => {
      const trimmed = text.trim();
      if (!trimmed || loading) return;

      const userMsg: Message = {
        id: crypto.randomUUID(),
        role: "user",
        content: trimmed,
      };
      const assistantId = crypto.randomUUID();
      const assistantMsg: Message = {
        id: assistantId,
        role: "assistant",
        content: "",
        streaming: true,
      };

      setMessages((prev) => [...prev, userMsg, assistantMsg]);
      setInput("");
      setLoading(true);
      setError(null);

      try {
        const history = messages.map((m) => ({ role: m.role, content: m.content }));

        const res = await fetch(`/api/scans/${scanId}/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: trimmed, history }),
        });

        if (!res.ok) {
          const data = (await res.json()) as { error?: string };
          throw new Error(data.error ?? "Failed to get response");
        }

        const reader = res.body!.getReader();
        const decoder = new TextDecoder();
        let accumulated = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const raw = decoder.decode(value, { stream: true });
          const lines = raw.split("\n");

          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const payload = line.slice(6).trim();
            if (payload === "[DONE]") break;

            try {
              const parsed = JSON.parse(payload) as string | { error: string };
              if (typeof parsed === "string") {
                accumulated += parsed;
                setMessages((prev) =>
                  prev.map((m) =>
                    m.id === assistantId
                      ? { ...m, content: accumulated, streaming: true }
                      : m,
                  ),
                );
              } else if (typeof parsed === "object" && parsed.error) {
                throw new Error(parsed.error);
              }
            } catch {
              // skip malformed chunks
            }
          }
        }

        // Mark streaming done
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantId ? { ...m, streaming: false } : m,
          ),
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Failed to get response";
        setError(msg);
        setMessages((prev) => prev.filter((m) => m.id !== assistantId));
      } finally {
        setLoading(false);
      }
    },
    [scanId, messages, loading],
  );

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void sendMessage(input);
    }
  }

  // ── Closed state: floating button ───────────────────────────────────────
  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-full bg-teal-600 px-4 py-3 text-sm font-medium text-white shadow-lg shadow-teal-600/30 transition-all hover:bg-teal-700 hover:shadow-xl hover:shadow-teal-600/40"
        aria-label="Open AI triage chat"
      >
        <MessageSquare className="h-4 w-4" />
        <span>Ask AI</span>
        {messages.length > 0 && (
          <Badge
            variant="secondary"
            className="ml-1 h-5 min-w-[20px] rounded-full bg-white/20 px-1 text-[10px] text-white"
          >
            {messages.filter((m) => m.role === "assistant").length}
          </Badge>
        )}
      </button>
    );
  }

  // ── Open state: chat panel ───────────────────────────────────────────────
  return (
    <div className="fixed bottom-6 right-6 z-50 flex w-[min(420px,calc(100vw-3rem))] flex-col rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
      {/* Header */}
      <div className="flex items-center justify-between rounded-t-2xl border-b border-slate-100 bg-gradient-to-r from-teal-600 to-cyan-600 px-4 py-3 dark:border-slate-800">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-white" />
          <span className="text-sm font-semibold text-white">AI Triage</span>
          <span className="text-[11px] text-teal-100">· Ask about these findings</span>
        </div>
        <div className="flex items-center gap-1">
          {messages.length > 0 && (
            <button
              type="button"
              onClick={() => setMessages([])}
              className="rounded p-1 text-teal-100 hover:bg-white/10 hover:text-white"
              title="Clear conversation"
            >
              <ChevronDown className="h-4 w-4" />
            </button>
          )}
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="rounded p-1 text-teal-100 hover:bg-white/10 hover:text-white"
            aria-label="Close chat"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div className="flex h-72 flex-col gap-3 overflow-y-auto px-4 py-3 scroll-smooth">
        {messages.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3">
            <p className="text-center text-xs text-muted-foreground">
              Ask anything about the scan findings.
            </p>
            <div className="flex flex-wrap justify-center gap-1.5">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => void sendMessage(s)}
                  className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] text-slate-600 transition-colors hover:border-teal-400 hover:bg-teal-50 hover:text-teal-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((msg) => (
            <div
              key={msg.id}
              className={cn(
                "flex gap-2",
                msg.role === "user" ? "flex-row-reverse" : "flex-row",
              )}
            >
              <div
                className={cn(
                  "flex h-6 w-6 shrink-0 items-center justify-center rounded-full",
                  msg.role === "user"
                    ? "bg-teal-600 text-white"
                    : "bg-slate-100 text-slate-600 dark:bg-slate-800",
                )}
              >
                {msg.role === "user" ? (
                  <User className="h-3 w-3" />
                ) : (
                  <Bot className="h-3 w-3" />
                )}
              </div>
              <div
                className={cn(
                  "max-w-[85%] rounded-2xl px-3 py-2 text-sm leading-relaxed",
                  msg.role === "user"
                    ? "rounded-tr-sm bg-teal-600 text-white"
                    : "rounded-tl-sm bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-200",
                )}
              >
                {msg.content || (
                  <span className="flex items-center gap-1.5 text-xs opacity-70">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    Thinking…
                  </span>
                )}
                {msg.streaming && msg.content && (
                  <span className="ml-0.5 inline-block h-3.5 w-0.5 animate-pulse bg-current opacity-70" />
                )}
              </div>
            </div>
          ))
        )}
        {error && (
          <p className="rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700 dark:bg-red-950/30 dark:text-red-400">
            {error}
          </p>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="border-t border-slate-100 px-3 py-3 dark:border-slate-800">
        <div className="flex items-end gap-2">
          <Textarea
            ref={textareaRef}
            rows={1}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about these findings… (Enter to send)"
            className="max-h-24 min-h-0 resize-none rounded-xl border-slate-200 bg-slate-50 text-sm dark:border-slate-700 dark:bg-slate-800"
            disabled={loading}
          />
          <Button
            size="icon"
            className="h-9 w-9 shrink-0 rounded-xl bg-teal-600 hover:bg-teal-700"
            disabled={!input.trim() || loading}
            onClick={() => void sendMessage(input)}
            aria-label="Send message"
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
          </Button>
        </div>
        <p className="mt-1.5 text-[10px] text-muted-foreground">
          Shift+Enter for new line · Uses your org&apos;s LLM config
        </p>
      </div>
    </div>
  );
}
