export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const nodeProcess = globalThis.process as NodeJS.Process | undefined;
  if (!nodeProcess?.on) return;

  // Catch unhandled errors from ioredis TLS reconnection attempts.
  // When a rediss:// connection times out, ioredis internally fires errors
  // on TLS sockets that may not have listeners attached yet, causing
  // "Cannot read properties of undefined (reading 'auth')" crashes.
  // This prevents the Next.js server from going down.
  nodeProcess.on("uncaughtException", (err) => {
    const msg = err?.message || "";
    if (
      msg.includes("Cannot read properties of undefined (reading 'auth')") ||
      msg.includes("connect ETIMEDOUT")
    ) {
      console.error("[instrumentation] Suppressed Redis TLS error:", msg);
      return; // swallow — Redis will reconnect via retryStrategy
    }
    // Re-throw anything else so Next.js default handler processes it
    console.error("[instrumentation] Uncaught exception:", err);
    throw err;
  });
}
