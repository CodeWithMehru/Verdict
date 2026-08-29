import "dotenv/config";
import { createClient } from "@supabase/supabase-js";
const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
async function run() {
  const ip = "10.13.37.2";
  const { error } = await supabase.from("threat_events").insert([
    { source: "trap_api", threat_type: "SQL_INJECTION", source_ip: ip, matched_pattern: "sqli_union_select", ai_analysis: "UNION-based SQL injection targeting user table" },
    { source: "trap_api", threat_type: "SQL_INJECTION", source_ip: ip, matched_pattern: "sqli_or_bypass", ai_analysis: "OR 1=1 authentication bypass attempt" },
    { source: "trap_api", threat_type: "SQL_INJECTION", source_ip: ip, matched_pattern: "sqli_union_select", ai_analysis: "UNION-based SQL injection targeting user table" },
    { source: "trap_api", threat_type: "SQL_INJECTION", source_ip: ip, matched_pattern: "sqli_or_bypass", ai_analysis: "OR 1=1 authentication bypass attempt" },
    { source: "trap_api", threat_type: "SENSITIVE_DATA_LEAK", source_ip: ip, matched_pattern: "api_key_leak", ai_analysis: "Attempted exfiltration of API key via POST body" }
  ]);
  console.log(error ? error : "seeded trap events");
}
run();
