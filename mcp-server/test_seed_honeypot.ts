import "dotenv/config";
import { createClient } from "@supabase/supabase-js";
const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
async function run() {
  const ip = "10.13.37.2";
  await supabase.from("threat_events").insert([
    { source: "honeypot", threat_type: "PORT_SCAN", source_ip: ip, metadata: { port: 2222, service: "ssh" } },
    { source: "honeypot", threat_type: "PORT_SCAN", source_ip: ip, metadata: { port: 63790, service: "redis" } }
  ]);
  console.log("seeded");
}
run();
