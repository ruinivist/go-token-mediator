import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createApp } from "../app.mjs";

class Element {
  constructor(tagName = "div") {
    this.tagName = tagName;
    this.children = [];
    this.listeners = {};
    this.attributes = {};
    this.hidden = false;
    this.disabled = false;
    this.href = "";
    this.className = "";
    this.open = tagName === "details" ? false : undefined;
    this._textContent = "";
  }

  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this._textContent = ""; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  removeAttribute(name) { delete this.attributes[name]; if (name === "href") this.href = ""; }
  setAttribute(name, value) { this.attributes[name] = value; }
  set textContent(value) { this._textContent = String(value); this.children = []; }
  get textContent() { return this._textContent + this.children.map((child) => child.textContent).join(""); }
  set innerHTML(_) { throw new Error("HTML output must not use innerHTML"); }
}

class Document {
  constructor() {
    this.elements = new Map();
    this.createdTags = [];
    for (const id of [
      "account-name", "account-login", "status", "connect-button", "continue-link",
      "token-button", "profile-button", "logout-button", "clear-button", "output",
    ]) this.elements.set(id, new Element("div"));
  }

  getElementById(id) { return this.elements.get(id); }
  createElement(tagName) {
    this.createdTags.push(tagName);
    return new Element(tagName);
  }
}

function response(status, body, headers = { "content-type": "application/json" }) {
  const serialized = typeof body === "string" ? body : JSON.stringify(body);
  return {
    status,
    statusText: status === 204 ? "No Content" : status === 200 ? "OK" : "Bad Request",
    ok: status >= 200 && status < 300,
    headers: { forEach(callback) { for (const [name, value] of Object.entries(headers)) callback(value, name); } },
    async text() { return serialized; },
  };
}

function harness({ fetch, href = "http://localhost:3000/" }) {
  const document = new Document();
  const replacements = [];
  const app = createApp({
    document,
    fetch,
    location: { href },
    history: { replaceState: (...args) => replacements.push(args) },
    performance: { now: (() => { let value = 0; return () => ++value; })() },
  });
  return { app, document, replacements };
}

function element(h, id) { return h.document.getElementById(id); }
async function click(h, id) { return element(h, id).listeners.click(); }
function descendants(element) { return element.children.flatMap((child) => [child, ...descendants(child)]); }

test("start request is fixed, credentialed, inspectable, and only links to GitHub OAuth", async () => {
  const calls = [];
  const authURL = "https://github.com/login/oauth/authorize?client_id=example&state=visible-state";
  const h = harness({ fetch: async (...args) => {
    calls.push(args);
    return response(200, { authorization_url: authURL });
  } });

  await click(h, "connect-button");

  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "http://localhost:8080/oauth/github/start");
  assert.deepEqual(calls[0][1], {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-OAuth-Bridge": "1" },
    body: "{}",
    credentials: "include",
    cache: "no-store",
  });
  assert.equal(element(h, "continue-link").href, authURL);
  assert.equal(element(h, "continue-link").hidden, false);
  assert.match(element(h, "output").textContent, /visible-state/);
  assert.match(element(h, "output").textContent, /HTTP 200 OK/);
  assert.ok(descendants(element(h, "output")).some((node) => node.tagName === "pre" && node.textContent === "{}"));
  assert.match(element(h, "status").textContent, /Inspect the start response/);
});

test("callback marker automatically retrieves a token then the GitHub profile safely as text", async () => {
  const token = "raw-test-token";
  const calls = [];
  const profile = { login: "<script>user</script>", name: "<img src=x onerror=alert(1)>" };
  const rawProfile = '{\n  "login": "<script>user</script>",\n  "name": "<img src=x onerror=alert(1)>"\n}\n';
  const h = harness({
    href: "http://localhost:3000/?keep=1&oauth=complete#top",
    fetch: async (...args) => {
      calls.push(args);
      return calls.length === 1
        ? response(200, { access_token: token, token_type: "Bearer" })
        : response(200, rawProfile, { "content-type": "application/json", "x-github-media-type": "github.v3" });
    },
  });

  await h.app.ready;

  assert.deepEqual(h.replacements[0], [null, "", "/?keep=1#top"]);
  assert.equal(calls.length, 2);
  assert.equal(calls[0][0], "http://localhost:8080/oauth/github/token");
  assert.equal(calls[0][1].method, "POST");
  assert.equal(calls[0][1].credentials, "include");
  assert.equal(calls[0][1].cache, "no-store");
  assert.equal(calls[1][0], "https://api.github.com/user");
  assert.equal(calls[1][1].method, "GET");
  assert.equal(calls[1][1].credentials, "omit");
  assert.equal(calls[1][1].headers.Authorization, `Bearer ${token}`);
  assert.match(element(h, "output").textContent, new RegExp(token));
  assert.doesNotMatch(element(h, "output").textContent, new RegExp(`Authorization: Bearer ${token}`));
  assert.match(element(h, "output").textContent, /x-github-media-type: github\.v3/);
  assert.match(element(h, "output").textContent, /<img src=x onerror=alert\(1\)>/);
  const outputNodes = descendants(element(h, "output"));
  const preformatted = outputNodes.filter((node) => node.tagName === "pre").map((node) => node.textContent);
  assert.ok(preformatted.includes(rawProfile));
  assert.ok(preformatted.includes("{}"));
  assert.ok(preformatted.includes("(no request body)"));
  assert.ok(outputNodes.filter((node) => node.tagName === "details").every((node) => node.open === false));
  assert.ok(outputNodes.some((node) => node.tagName === "summary" && node.textContent === "Request headers (Authorization omitted)"));
  assert.ok(outputNodes.some((node) => node.tagName === "summary" && node.textContent === "Response headers (browser-readable)"));
  assert.equal(element(h, "account-name").textContent, profile.name);
  assert.equal(element(h, "account-login").textContent, `@${profile.login}`);
  assert.equal(h.document.createdTags.includes("img"), false);
  assert.match(element(h, "status").textContent, /profile loaded/i);
});

test("network/CORS failures and untrusted authorization URLs are visible but never followed", async () => {
  let count = 0;
  const h = harness({ fetch: async () => {
    count += 1;
    if (count === 1) throw new TypeError("Failed to fetch");
    return response(200, { authorization_url: "https://evil.example/login/oauth/authorize" });
  } });

  await click(h, "connect-button");
  assert.match(element(h, "status").textContent, /Network\/CORS error: Failed to fetch/);
  assert.match(element(h, "status").textContent, /request output below/);
  assert.match(element(h, "output").textContent, /Failed to fetch/);
  await click(h, "connect-button");
  assert.equal(element(h, "continue-link").hidden, true);
  assert.match(element(h, "status").textContent, /unexpected authorization URL/);
});

test("cookie copy describes configured policy without claiming browser-observed state", () => {
  const markup = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const app = readFileSync(new URL("../app.mjs", import.meta.url), "utf8");

  assert.match(markup, /__Host-oauth_bridge/);
  assert.match(markup, /HttpOnly · Secure · SameSite=Lax · Path=\//);
  assert.match(markup, /JavaScript cannot read this cookie or confirm its presence/);
  assert.match(markup, /not a report of whether a cookie is present/);
  assert.match(markup, /DevTools → Application → Cookies → localhost/);
  assert.doesNotMatch(app, /document\.cookie/);
});

test("successful logout clears token-bearing output and account state without claiming token revocation", async () => {
  const token = "logout-sensitive-token";
  const calls = [];
  const h = harness({ fetch: async (...args) => {
    calls.push(args);
    return calls.length === 1
      ? response(200, { access_token: token })
      : response(204, "");
  } });

  await click(h, "token-button");
  assert.match(element(h, "output").textContent, new RegExp(token));
  await click(h, "logout-button");

  assert.equal(calls[1][0], "http://localhost:8080/session/logout");
  assert.equal(calls[1][1].method, "POST");
  assert.equal(calls[1][1].credentials, "include");
  assert.equal(calls[1][1].body, "{}");
  assert.doesNotMatch(element(h, "output").textContent, new RegExp(token));
  assert.equal(element(h, "account-name").textContent, "Not connected");
  assert.match(element(h, "status").textContent, /does not revoke the GitHub token/);
  await click(h, "profile-button");
  assert.equal(calls.length, 2);
  assert.match(element(h, "status").textContent, /Get a token first/);
});

test("overlapping operations do not send another request", async () => {
  let finish;
  let calls = 0;
  const h = harness({ fetch: () => {
    calls += 1;
    return new Promise((resolve) => { finish = resolve; });
  } });

  const connecting = click(h, "connect-button");
  assert.equal(element(h, "token-button").disabled, true);
  await click(h, "token-button");
  assert.equal(calls, 1);
  finish(response(200, { authorization_url: "https://github.com/login/oauth/authorize?state=test" }));
  await connecting;
});
