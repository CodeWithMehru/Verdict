# Verdict Console (UI)

Source for the Verdict Console — the live agent UI (tool-call activity, timeline/evidence,
approval state panels).

For this hackathon it runs as a route inside Triage's existing Next.js dashboard (kept as a
separate page — Triage's own screens were not modified). This folder holds a copy of that
route's source for review.

To run it live:
1. Start Triage's dashboard: `cd Triage/dashboard && npm run dev`
2. Open `http://localhost:3000/verdict-console`
