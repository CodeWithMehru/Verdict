import "dotenv/config";
import { createClient } from "@supabase/supabase-js";
const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
async function run() {
  const { data, error } = await supabase.from("threat_events").select("source_ip, threat_type, created_at").order("created_at", { ascending: false }).limit(10);
  console.log(JSON.stringify(data, null, 2));
}
run();
