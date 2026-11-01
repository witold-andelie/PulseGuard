export const RENDER = "https://pulseguard-dufi.onrender.com";

export function cloudRunUrl(value) {
  return typeof value === "string" && /^https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.run\.app$/.test(value) ? value : "";
}

// Pure policy: only an observable HTTP 200 from a valid Cloud Run origin wins.
export function chooseEndpoint(cloudRun, status) {
  return cloudRunUrl(cloudRun) && status === 200 ? cloudRun : RENDER;
}

export async function boundedFetch(url, {fetchImpl = fetch, timeoutMs = 8000, json = false} = {}) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      fetchImpl(url, {signal: controller.signal, cache: "no-store", credentials: "omit", redirect: "error"})
        .then(async response => json ? (response.status === 200 ? response.json() : {}) : response),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error("Probe timed out"));
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export async function probeCloudRun(url, options) {
  if (!cloudRunUrl(url)) return 0;
  try {
    const response = await boundedFetch(`${url}/health`, options);
    return response.status;
  } catch {
    return 0;
  }
}

async function start() {
  const status = document.getElementById("status");
  const stay = document.getElementById("stay");
  let stopped = false;
  stay.hidden = false;
  stay.addEventListener("click", () => {
    stopped = true;
    status.textContent = "Automatic redirect stopped. Choose either deployment link.";
    stay.hidden = true;
  });
  status.textContent = "Loading deployment links…";
  let cloudRun = "";
  try {
    const endpoints = await boundedFetch(new URL("endpoints.json", import.meta.url), {json: true});
    cloudRun = cloudRunUrl(endpoints.cloudRun);
  } catch { /* A missing configuration always leaves Render available. */ }
  if (cloudRun) {
    const link = document.getElementById("cloud-run-link");
    link.href = cloudRun;
    link.hidden = false;
  }
  if (stopped) return;
  status.textContent = cloudRun ? "Checking Google Cloud (up to 8 seconds; a cold start can take a few)…" : "Google Cloud is not configured. Opening Render…";
  const code = await probeCloudRun(cloudRun);
  if (stopped) return;
  const target = chooseEndpoint(cloudRun, code);
  status.textContent = target === RENDER ? "Google Cloud is unavailable. Opening Render…" : "Google Cloud is healthy. Opening PulseGuard…";
  // Gives the status and stop control time to be read. Preserve the app's hash route.
  setTimeout(() => {
    if (!stopped) window.location.replace(target + window.location.hash);
  }, 1200);
}

if (typeof document !== "undefined") {
  start().catch(() => { window.location.replace(RENDER); });
}
