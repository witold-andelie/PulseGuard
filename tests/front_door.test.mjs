import test from "node:test";
import assert from "node:assert/strict";
import {RENDER, boundedFetch, chooseEndpoint, probeCloudRun} from "../site/front-door.mjs";

const cloud = "https://pulseguard-123.europe-west3.run.app";

test("only a valid Cloud Run URL and HTTP 200 wins", () => {
  assert.equal(chooseEndpoint(cloud, 200), cloud);
  const hashed = "https://pulseguard-abcdefgh-ey.a.run.app";
  assert.equal(chooseEndpoint(hashed, 200), hashed);
  for (const status of [0, 201, 204, 302, 403, 404, 500, 503, undefined, "200"]) {
    assert.equal(chooseEndpoint(cloud, status), RENDER);
  }
  for (const url of ["", null, "javascript:alert(1)", "https://evil.example", `${cloud}/path`, `${cloud}.evil.test`, "https://user@x.run.app"]) {
    assert.equal(chooseEndpoint(url, 200), RENDER);
  }
});

test("observable health statuses reach the pure policy", async () => {
  let called;
  const status = await probeCloudRun(cloud, {fetchImpl: async (url, options) => {
    called = url;
    assert.equal(options.credentials, "omit");
    assert.equal(options.cache, "no-store");
    assert.equal(options.redirect, "error");
    return {status: 200};
  }});
  assert.equal(called, `${cloud}/health`);
  assert.equal(chooseEndpoint(cloud, status), cloud);
  assert.equal(await probeCloudRun(cloud, {fetchImpl: async () => ({status: 503})}), 503);
});

test("network and CORS errors fail over", async () => {
  const status = await probeCloudRun(cloud, {fetchImpl: async () => { throw new TypeError("Failed to fetch"); }});
  assert.equal(chooseEndpoint(cloud, status), RENDER);
});

test("timeout fails over even when transport ignores AbortSignal", async () => {
  let signal;
  const status = await probeCloudRun(cloud, {timeoutMs: 10, fetchImpl: (_url, options) => {
    signal = options.signal;
    return new Promise(() => {});
  }});
  assert.equal(status, 0);
  assert.equal(signal.aborted, true);
});

test("unconfigured deployment never probes", async () => {
  const fetchImpl = () => { throw new Error("Should not fetch"); };
  assert.equal(await probeCloudRun("", {fetchImpl}), 0);
});

test("configuration body timeout is bounded too", async () => {
  await assert.rejects(boundedFetch("https://pages.example/endpoints.json", {
    json: true, timeoutMs: 10,
    fetchImpl: async () => ({status: 200, json: () => new Promise(() => {})}),
  }), /timed out/);
});
