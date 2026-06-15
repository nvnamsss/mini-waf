import { WafApiClient } from "./api/client.js";
import { WafFeedClient } from "./api/ws.js";
import { ChartsComponent } from "./components/Charts.js";
import { ConfigComponent } from "./components/Config.js";
import { FeedComponent } from "./components/Feed.js";

const WAF_API_BASE = process.env.WAF_API_URL ?? "http://localhost:9090";
const WAF_WS_URL   = process.env.WAF_WS_URL  ?? "ws://localhost:9090/ws/feed";

async function main(): Promise<void> {
  const api    = new WafApiClient(WAF_API_BASE);
  const feed   = new FeedComponent();
  const charts = new ChartsComponent();
  const config = new ConfigComponent(api);

  // Subscribe to live audit stream.
  const ws = new WafFeedClient(WAF_WS_URL);
  ws.connect((entry) => {
    feed.push(entry);
  });

  // Poll metrics every 5 seconds.
  setInterval(async () => {
    // TODO: call api.getMetrics(); charts.update(metrics);
  }, 5_000);

  // Initial rule load.
  await config.loadRules();
}

main().catch(console.error);
