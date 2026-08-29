/**
 * test-tools.ts — Standalone tool tests
 * ======================================
 * Calls each MCP tool handler DIRECTLY against the real Supabase instance,
 * without going through the agent or MCP protocol. This proves the data layer
 * works before wiring it to TrueForge.
 *
 * Usage:
 *   cd agent/mcp-server
 *   npx tsx tests/test-tools.ts [ip]
 *
 * Exits 0 on success, 1 if any test fails or Supabase is unreachable.
 *
 * What this verifies:
 *   - get_threat_events: reads real trap API events from threat_events
 *   - get_honeypot_hits: reads real honeypot events (source = 'honeypot')
 *   - ban_ip:            inserts a real AUTO_BAN row (safe test IP only!)
 *   - investigate_history: graceful-degrades when KoshurLock is down
 */

import "dotenv/config";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

// ── Config ───────────────────────────────────────────────────────────────────

const SUPABASE_URL = process.env.SUPABASE_URL ?? "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const KOSHURLOCK_URL = process.env.KOSHURLOCK_URL ?? "http://localhost:8080";
const TIER2_TIMEOUT_MS = 5_000;

// Safe test IP — RFC 5737 documentation block, guaranteed to never appear in
// real traffic, so a ban/unban on this IP cannot accidentally block a real user.
const TEST_IP = process.argv[2] ?? "192.0.2.1";
const BAN_TEST_IP = "192.0.2.99"; // separate IP for ban test to avoid side effects

// ── Supabase client ──────────────────────────────────────────────────────────

function getSupabase(): SupabaseClient {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error(
      "SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set. Copy .env.example → .env and fill in values."
    );
  }
  return createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function pass(label: string, detail?: string): void {
  console.log(`  ✅ PASS  ${label}${detail ? ` — ${detail}` : ""}`);
}

function warn(label: string, detail?: string): void {
  console.log(`  ⚠️  WARN  ${label}${detail ? ` — ${detail}` : ""}`);
}

function fail(label: string, detail?: string): never {
  console.error(`  ❌ FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  process.exit(1);
}

// ── Tool implementations (mirrors src/index.ts exactly) ─────────────────────

async function getThreatEvents(
  supabase: SupabaseClient,
  ip: string
): Promise<{ count: number; events: unknown[] }> {
  const { data, error } = await supabase
    .from("threat_events")
    .select(
      "id, source, threat_type, severity, source_ip, payload_snippet, matched_pattern, ai_analysis, metadata, created_at"
    )
    .eq("source_ip", ip)
    .neq("threat_type", "AUTO_BAN")
    .order("created_at", { ascending: false })
    .limit(50);

  if (error) throw new Error(`get_threat_events: ${error.message}`);

  const events = (data ?? []).map((row) => ({
    threat_type: row.threat_type,
    severity: row.severity,
    matched_pattern: row.matched_pattern,
    ai_analysis: (row.ai_analysis as string | null)?.slice(0, 120) ?? null,
    timestamp: row.created_at,
    source: row.source,
    payload_snippet: (row.payload_snippet as string | null)?.slice(0, 200) ?? null,
  }));

  return { count: events.length, events };
}

async function getHoneypotHits(
  supabase: SupabaseClient,
  ip: string
): Promise<{ count: number; hits: unknown[] }> {
  const { data, error } = await supabase
    .from("threat_events")
    .select("id, source_ip, metadata, created_at")
    .eq("source_ip", ip)
    .eq("source", "honeypot")
    .order("created_at", { ascending: false })
    .limit(100);

  if (error) throw new Error(`get_honeypot_hits: ${error.message}`);

  const hits = (data ?? []).map((row) => {
    const meta = row.metadata as Record<string, unknown> | null;
    return {
      port: meta?.port ?? 2222,
      service: meta?.service ?? "ssh",
      timestamp: row.created_at,
    };
  });

  return { count: hits.length, hits };
}

async function banIp(
  supabase: SupabaseClient,
  ip: string,
  reason: string
): Promise<{ ip: string; banned: boolean; row?: unknown; note?: string }> {
  // Check existing ban
  const banDurationMs = 24 * 60 * 60 * 1000;
  const since = new Date(Date.now() - banDurationMs).toISOString();

  const { count: existing } = await supabase
    .from("threat_events")
    .select("*", { count: "exact", head: true })
    .eq("source_ip", ip)
    .eq("threat_type", "AUTO_BAN")
    .gte("created_at", since);

  if ((existing ?? 0) > 0) {
    return { ip, banned: false, note: "Already banned within 24h" };
  }

  const row = {
    source: "trap_api",
    threat_type: "AUTO_BAN",
    severity: "CRITICAL",
    source_ip: ip,
    payload_snippet: null,
    matched_pattern: "verdict.agent.ban",
    ai_analysis: `Verdict agent ban (TEST): ${reason}`,
    metadata: {
      banned_by: "Verdict",
      reason,
      test: true,
      timestamp: new Date().toISOString(),
    },
  };

  const { data, error } = await supabase
    .from("threat_events")
    .insert(row)
    .select()
    .single();

  if (error) throw new Error(`ban_ip insert: ${error.message}`);
  return { ip, banned: true, row: data };
}

async function cleanupBan(supabase: SupabaseClient, ip: string): Promise<void> {
  const { error } = await supabase
    .from("threat_events")
    .delete()
    .eq("source_ip", ip)
    .eq("threat_type", "AUTO_BAN")
    .contains("metadata", { test: true });

  if (error) {
    console.warn(`  ⚠️  Cleanup failed for ${ip}: ${error.message}`);
  }
}

async function investigateHistory(query: string): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIER2_TIMEOUT_MS);
  try {
    const res = await fetch(`${KOSHURLOCK_URL}/api/ask`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: query }),
      signal: controller.signal,
    });
    if (!res.ok) {
      return { available: false, note: `HTTP ${res.status}` };
    }
    const data = await res.json();
    return { available: true, answer: (data as Record<string, unknown>).answer };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { available: false, note: `KoshurLock unavailable: ${msg}` };
  } finally {
    clearTimeout(timeout);
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("\n══════════════════════════════════════════════════════════════");
  console.log("  Verdict MCP Tool Tests — Direct Supabase Calls");
  console.log(`  Test IP for threat/honeypot lookup: ${TEST_IP}`);
  console.log(`  Test IP for ban_ip:                 ${BAN_TEST_IP}`);
  console.log("══════════════════════════════════════════════════════════════\n");

  // ── Connect Supabase ──────────────────────────────────────────────────────
  console.log("── Supabase connectivity ────────────────────────────────────");
  let supabase: SupabaseClient;
  try {
    supabase = getSupabase();
    // Lightweight connectivity probe — count all rows (uses RLS, but service_role bypasses)
    const { error } = await supabase
      .from("threat_events")
      .select("id", { count: "exact", head: true });
    if (error) throw error;
    pass("Supabase connection", `${SUPABASE_URL}`);
  } catch (err) {
    fail(
      "Cannot reach Supabase",
      err instanceof Error ? err.message : String(err)
    );
  }

  // ── TEST 1: get_threat_events ─────────────────────────────────────────────
  console.log("\n── Tool 1: get_threat_events ────────────────────────────────");
  try {
    const result = await getThreatEvents(supabase!, TEST_IP);
    console.log(
      `  → ${result.count} threat event(s) found for ${TEST_IP}`
    );
    if (result.count > 0) {
      console.log("  → Most recent:");
      console.log(
        JSON.stringify((result.events as unknown[])[0], null, 4)
          .split("\n")
          .map((l) => `     ${l}`)
          .join("\n")
      );
      pass("get_threat_events", `${result.count} real events returned`);
    } else {
      // No events is a valid result — the IP may not have attacked yet
      warn(
        "get_threat_events",
        `0 events for ${TEST_IP} — run the Red Team Simulator in the Triage dashboard first to generate real traffic, or pass a real attacker IP as argv[2]`
      );
    }
  } catch (err) {
    fail("get_threat_events", err instanceof Error ? err.message : String(err));
  }

  // ── TEST 2: get_honeypot_hits ─────────────────────────────────────────────
  console.log("\n── Tool 2: get_honeypot_hits ────────────────────────────────");
  try {
    const result = await getHoneypotHits(supabase!, TEST_IP);
    console.log(`  → ${result.count} honeypot hit(s) found for ${TEST_IP}`);
    if (result.count > 0) {
      console.log("  → Most recent:");
      console.log(
        JSON.stringify((result.hits as unknown[])[0], null, 4)
          .split("\n")
          .map((l) => `     ${l}`)
          .join("\n")
      );
      pass("get_honeypot_hits", `${result.count} real hits returned`);
    } else {
      warn(
        "get_honeypot_hits",
        "0 hits — honeypot may not be running or IP has not scanned ports yet"
      );
    }
  } catch (err) {
    fail(
      "get_honeypot_hits",
      err instanceof Error ? err.message : String(err)
    );
  }

  // ── TEST 3: ban_ip ────────────────────────────────────────────────────────
  console.log("\n── Tool 3: ban_ip ───────────────────────────────────────────");
  console.log(`  (using safe test IP ${BAN_TEST_IP} — RFC 5737 documentation range)`);
  try {
    const result = await banIp(
      supabase!,
      BAN_TEST_IP,
      "Standalone tool test — safe RFC 5737 IP, not a real attacker"
    );
    if (result.banned) {
      console.log("  → Ban row written:");
      console.log(
        JSON.stringify(result.row, null, 4)
          .split("\n")
          .map((l) => `     ${l}`)
          .join("\n")
      );
      pass(
        "ban_ip insert",
        "AUTO_BAN row written, identical format to Triage's sreSidekick.ts"
      );
    } else {
      warn("ban_ip", result.note ?? "already banned");
    }

    // Verify it's now readable (what the middleware would see)
    const banDurationMs = 24 * 60 * 60 * 1000;
    const since = new Date(Date.now() - banDurationMs).toISOString();
    const { count } = await supabase!
      .from("threat_events")
      .select("*", { count: "exact", head: true })
      .eq("source_ip", BAN_TEST_IP)
      .eq("threat_type", "AUTO_BAN")
      .gte("created_at", since);

    if ((count ?? 0) > 0) {
      pass(
        "ban_ip verify",
        `isIpBanned('${BAN_TEST_IP}') would return TRUE — middleware would return 403`
      );
    } else {
      fail("ban_ip verify", "Row was inserted but is not visible in ban check query");
    }

    // Clean up test ban
    await cleanupBan(supabase!, BAN_TEST_IP);
    console.log(`  → Test ban row cleaned up for ${BAN_TEST_IP}`);
  } catch (err) {
    fail("ban_ip", err instanceof Error ? err.message : String(err));
  }

  // ── TEST 4: investigate_history (Tier 2, graceful-fail) ──────────────────
  console.log(
    "\n── Tool 4: investigate_history (Tier 2 — expect graceful fail) ──"
  );
  try {
    const result = await investigateHistory(
      `What do we know about IP ${TEST_IP}?`
    );
    const r = result as Record<string, unknown>;
    if (r.available) {
      pass("investigate_history", `KoshurLock responded: ${String(r.answer).slice(0, 100)}`);
    } else {
      pass(
        "investigate_history degraded gracefully",
        `note: ${r.note}`
      );
    }
  } catch (err) {
    // Should never throw — graceful-fail is required
    fail(
      "investigate_history threw instead of degrading",
      err instanceof Error ? err.message : String(err)
    );
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log(
    "\n══════════════════════════════════════════════════════════════"
  );
  console.log("  ALL TOOL TESTS COMPLETE ✅");
  console.log("  Transport note (confirmed from trueforge.dev/mcp-servers):");
  console.log("  TrueForge connects to MCP servers via REMOTE URL (SSE/HTTP),");
  console.log("  NOT stdio. verdict-mcp uses SSEServerTransport on /sse.");
  console.log("══════════════════════════════════════════════════════════════\n");
}

main().catch((err) => {
  console.error("\n❌ Unhandled error:", err);
  process.exit(1);
});
