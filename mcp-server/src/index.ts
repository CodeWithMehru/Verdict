/**
 * Verdict MCP Server
 * ==================
 *
 * Exposes tools to TrueForge for investigating and acting on threat events.
 *
 * Tier 1 (standalone — Triage DB only):
 *   - get_threat_events(ip)   — fetch attack events for an IP from Supabase
 *   - get_honeypot_hits(ip)   — fetch port-scan events for an IP
 *   - ban_ip(ip, reason)      — insert AUTO_BAN row (⚠️ requires human approval)
 *
 * Tier 2 (optional — graceful degradation):
 *   - investigate_history(query) — recall from KoshurLock-Holmes knowledge graph
 *
 * Transport:
 *   POST /mcp  — Streamable HTTP (MCP spec 2025-11-25, TrueForge primary)
 *   GET  /sse  — SSE legacy transport (TrueForge fallback)
 *
 * IMPORTANT: Each transport connection gets its own McpServer instance.
 * The SDK does not allow one McpServer to connect to multiple transports.
 */

import "dotenv/config";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import express from "express";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { z } from "zod";
import crypto from "crypto";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = Number(process.env.MCP_PORT ?? 8000);
const SUPABASE_URL = process.env.SUPABASE_URL ?? "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const KOSHURLOCK_URL = process.env.KOSHURLOCK_URL ?? "http://localhost:8080";
const TIER2_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// Supabase client (lazy singleton — survives missing env gracefully)
// ---------------------------------------------------------------------------

let _supabase: SupabaseClient | null = null;

function getSupabase(): SupabaseClient | null {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.warn("[verdict-mcp] SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set");
    return null;
  }
  if (!_supabase) {
    _supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return _supabase;
}

// ---------------------------------------------------------------------------
// MCP Server factory
// ---------------------------------------------------------------------------
// Each transport connection (SSE or Streamable HTTP) needs its own McpServer
// instance. The SDK raises "Already connected to a transport" if you reuse one.
// We register all four tools on every new instance via registerTools().

function registerTools(s: McpServer): void {

  // ── get_threat_events ─────────────────────────────────────────────────────

  s.tool(
    "get_threat_events",
    "Fetch all threat events (SQLi, XSS, data leak, etc.) for a given IP from Triage's Supabase database. Returns up to 50 most recent events.",
    { ip: z.string().describe("The IP address to investigate") },
    async ({ ip }) => {
      const supabase = getSupabase();
      if (!supabase) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: "Supabase not configured", events: [] }) }],
          isError: true,
        };
      }

      const { data, error } = await supabase
        .from("threat_events")
        .select("id, source, threat_type, severity, source_ip, payload_snippet, matched_pattern, ai_analysis, metadata, created_at")
        .eq("source_ip", ip)
        .neq("threat_type", "AUTO_BAN")
        .order("created_at", { ascending: false })
        .limit(50);

      if (error) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: error.message, events: [] }) }],
          isError: true,
        };
      }

      const events = (data ?? []).map((row) => ({
        threat_type: row.threat_type,
        severity: row.severity,
        matched_pattern: row.matched_pattern,
        ai_analysis: row.ai_analysis,
        timestamp: row.created_at,
        source: row.source,
        payload_snippet: (row.payload_snippet as string | null)?.slice(0, 200) ?? null,
      }));

      return {
        content: [{ type: "text", text: JSON.stringify({ ip, count: events.length, events }) }],
      };
    }
  );

  // ── get_honeypot_hits ─────────────────────────────────────────────────────

  s.tool(
    "get_honeypot_hits",
    "Fetch honeypot port-scan events for a given IP from Triage's Supabase database. Returns up to 100 most recent hits.",
    { ip: z.string().describe("The IP address to investigate") },
    async ({ ip }) => {
      const supabase = getSupabase();
      if (!supabase) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: "Supabase not configured", hits: [] }) }],
          isError: true,
        };
      }

      const { data, error } = await supabase
        .from("threat_events")
        .select("id, source_ip, metadata, created_at")
        .eq("source_ip", ip)
        .eq("source", "honeypot")
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: error.message, hits: [] }) }],
          isError: true,
        };
      }

      const hits = (data ?? []).map((row) => {
        const meta = row.metadata as Record<string, unknown> | null;
        return {
          port: meta?.port ?? 2222,
          service: meta?.service ?? "ssh",
          timestamp: row.created_at,
        };
      });

      return {
        content: [{ type: "text", text: JSON.stringify({ ip, count: hits.length, hits }) }],
      };
    }
  );

  // ── ban_ip (⚠️ DESTRUCTIVE — requires human approval checkpoint) ──────────

  s.tool(
    "ban_ip",
    "⚠️ IRREVERSIBLE — Ban an IP address by inserting an AUTO_BAN row into Triage's threat_events table. The Triage middleware will immediately return 403 for this IP. This tool MUST only be called after explicit human approval through TrueForge's approval checkpoint.",
    {
      ip: z.string().describe("The IP address to ban"),
      reason: z.string().describe("Human-readable reason for the ban, from the investigation summary"),
    },
    async ({ ip, reason }) => {
      const supabase = getSupabase();
      if (!supabase) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: "Supabase not configured", banned: false }) }],
          isError: true,
        };
      }

      // Check existing ban (same logic as Triage's isIpBanned())
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const { count: existingBan } = await supabase
        .from("threat_events")
        .select("*", { count: "exact", head: true })
        .eq("source_ip", ip)
        .eq("threat_type", "AUTO_BAN")
        .gte("created_at", since);

      if ((existingBan ?? 0) > 0) {
        return {
          content: [{ type: "text", text: JSON.stringify({ ip, banned: false, reason: "IP is already banned within the last 24 hours" }) }],
        };
      }

      // Insert ban row — exact same format as Triage's sreSidekick.ts
      const { error } = await supabase.from("threat_events").insert({
        source: "trap_api",
        threat_type: "AUTO_BAN",
        severity: "CRITICAL",
        source_ip: ip,
        payload_snippet: null,
        matched_pattern: "verdict.agent.ban",
        ai_analysis: `Verdict agent ban: ${reason}`,
        metadata: {
          banned_by: "Verdict",
          reason,
          timestamp: new Date().toISOString(),
        },
      });

      if (error) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: error.message, banned: false }) }],
          isError: true,
        };
      }

      return {
        content: [{ type: "text", text: JSON.stringify({
          ip,
          banned: true,
          reason,
          message: `IP ${ip} has been banned. Triage middleware will now return 403 IP_AUTO_BANNED for all requests from this IP.`,
        }) }],
      };
    }
  );

  // ── investigate_history (Tier 2, graceful-fail) ───────────────────────────

  s.tool(
    "investigate_history",
    "Tier 2 (optional) — Ask KoshurLock-Holmes knowledge graph if there is any prior history for an IP or attack pattern. Degrades gracefully if KoshurLock is unavailable.",
    { query: z.string().describe("Plain-English question about an IP or attack pattern") },
    async ({ query }) => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      try {
        const res = await fetch(`${KOSHURLOCK_URL}/api/ask`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question: query, want_timeline: true }),
          signal: controller.signal,
        });
        if (!res.ok) {
          return {
            content: [{ type: "text", text: "No historical correlation available for this query." }],
          };
        }
        const data = (await res.json()) as Record<string, unknown>;
        return {
          content: [{ type: "text", text: JSON.stringify({ available: true, answer: data.answer ?? data.response ?? JSON.stringify(data) }) }],
        };
      } catch (err) {
        return {
          content: [{ type: "text", text: "No historical correlation available for this query." }],
        };
      } finally {
        clearTimeout(timeout);
      }
    }
  );

  // ── flag_leak (Optional Extra Action) ─────────────────────────────────────

  s.tool(
    "flag_leak",
    "⚠️ Requires Human Approval. Create a flagged row in Supabase for a detected leaked secret pattern instead of or in addition to banning.",
    {
      ip: z.string().describe("The IP address associated with the leak"),
      pattern: z.string().describe("The detected secret pattern"),
    },
    async ({ ip, pattern }) => {
      const supabase = getSupabase();
      if (!supabase) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: "Supabase not configured", flagged: false }) }],
          isError: true,
        };
      }

      const { error } = await supabase.from("threat_events").insert({
        source: "trap_api",
        threat_type: "LEAK_FLAG",
        severity: "HIGH",
        source_ip: ip,
        payload_snippet: null,
        matched_pattern: pattern,
        ai_analysis: `Verdict agent flagged a leak for pattern: ${pattern}`,
        metadata: {
          flagged_by: "Verdict",
          pattern,
          timestamp: new Date().toISOString(),
        },
      });

      if (error) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: error.message, flagged: false }) }],
          isError: true,
        };
      }

      return {
        content: [{ type: "text", text: JSON.stringify({
          ip,
          flagged: true,
          message: `IP ${ip} with pattern ${pattern} has been flagged for leaked secrets in the threat_events table.`,
        }) }],
      };
    }
  );
}

function createServer(): McpServer {
  const s = new McpServer({ name: "verdict-mcp", version: "0.1.0" });
  registerTools(s);
  return s;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

// Health check (unauthenticated)
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "verdict-mcp", version: "0.1.0" });
});

// ── Streamable HTTP Transport (TrueForge primary) ─────────────────────────
// POST /mcp  — client sends initialize + subsequent messages here
// GET  /mcp  — client upgrades to SSE stream (for streaming responses)
// DELETE /mcp — session teardown

const httpSessions: Map<string, StreamableHTTPServerTransport> = new Map();

app.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (sessionId && httpSessions.has(sessionId)) {
    // Existing session — route message to its transport
    await httpSessions.get(sessionId)!.handleRequest(req, res, req.body);
    return;
  }

  if (!sessionId && isInitializeRequest(req.body)) {
    // New session
    const newId = crypto.randomUUID();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => newId,
      onsessioninitialized: (id) => {
        httpSessions.set(id, transport);
        console.log(`[verdict-mcp] /mcp session opened: ${id}`);
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) {
        httpSessions.delete(transport.sessionId);
        console.log(`[verdict-mcp] /mcp session closed: ${transport.sessionId}`);
      }
    };
    const server = createServer();
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    return;
  }

  res.status(400).json({ error: "Provide mcp-session-id header or send an initialize request" });
});

app.get("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !httpSessions.has(sessionId)) {
    res.status(400).json({ error: "Unknown mcp-session-id" });
    return;
  }
  await httpSessions.get(sessionId)!.handleRequest(req, res);
});

app.delete("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (sessionId && httpSessions.has(sessionId)) {
    await httpSessions.get(sessionId)!.close();
    httpSessions.delete(sessionId);
    console.log(`[verdict-mcp] /mcp session deleted: ${sessionId}`);
  }
  res.status(204).end();
});

// ── SSE Transport (TrueForge fallback) ───────────────────────────────────
// GET  /sse     — opens event stream, returns sessionId in first event
// POST /message — client sends JSON-RPC messages here

const sseSessions: Record<string, SSEServerTransport> = {};

app.get("/sse", async (_req, res) => {
  const transport = new SSEServerTransport("/message", res);
  sseSessions[transport.sessionId] = transport;
  res.on("close", () => {
    delete sseSessions[transport.sessionId];
    console.log(`[verdict-mcp] /sse session closed: ${transport.sessionId}`);
  });
  console.log(`[verdict-mcp] /sse session opened: ${transport.sessionId}`);
  const server = createServer();
  await server.connect(transport);
});

app.post("/message", async (req, res) => {
  const sessionId = req.query.sessionId as string;
  const transport = sseSessions[sessionId];
  if (!transport) {
    res.status(400).json({ error: "Unknown SSE session", sessionId });
    return;
  }
  await transport.handlePostMessage(req, res);
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`[verdict-mcp] MCP server listening on http://localhost:${PORT}`);
  console.log(`[verdict-mcp] Streamable HTTP (primary): http://localhost:${PORT}/mcp`);
  console.log(`[verdict-mcp] SSE (fallback):            http://localhost:${PORT}/sse`);
  console.log(`[verdict-mcp] Health:                    http://localhost:${PORT}/health`);
  console.log(`[verdict-mcp] Supabase: ${SUPABASE_URL ? "configured ✓" : "NOT SET ✗"}`);
  console.log(`[verdict-mcp] KoshurLock: ${KOSHURLOCK_URL}`);
});
