const MEDIATOR = "http://localhost:8080";
const GITHUB_USER = "https://api.github.com/user";
const POST_HEADERS = {
  "Content-Type": "application/json",
  "X-OAuth-Bridge": "1",
};

export function createApp({
  document,
  fetch: request = globalThis.fetch,
  location = globalThis.location,
  history = globalThis.history,
  performance = globalThis.performance,
}) {
  const elements = Object.fromEntries([
    "account-name", "account-login", "status", "connect-button", "continue-link",
    "token-button", "profile-button", "logout-button", "clear-button", "output",
  ].map((id) => [id, document.getElementById(id)]));
  const state = { token: null, busy: false, entries: [] };
  const actionButtons = [
    elements["connect-button"], elements["token-button"], elements["profile-button"],
    elements["logout-button"], elements["clear-button"],
  ];

  function setStatus(message) {
    elements.status.textContent = message;
  }

  function setBusy(busy) {
    state.busy = busy;
    for (const button of actionButtons) button.disabled = busy;
  }

  function section(label, value) {
    const wrapper = document.createElement("section");
    wrapper.className = "log-section";
    const heading = document.createElement("h3");
    heading.textContent = label;
    const pre = document.createElement("pre");
    pre.textContent = value;
    wrapper.append(heading, pre);
    return wrapper;
  }

  function headerDetails(label, value) {
    const details = document.createElement("details");
    details.className = "log-details";
    const summary = document.createElement("summary");
    summary.textContent = label;
    const pre = document.createElement("pre");
    pre.textContent = value;
    details.append(summary, pre);
    return details;
  }

  function renderEntries() {
    elements.output.replaceChildren();
    if (state.entries.length === 0) {
      const empty = document.createElement("p");
      empty.className = "empty-output";
      empty.textContent = "Requests and raw response bodies will appear here. Nothing is saved to browser storage.";
      elements.output.append(empty);
      return;
    }
    for (const entry of state.entries) {
      const article = document.createElement("article");
      article.className = "log-entry";
      const heading = document.createElement("header");
      heading.className = "log-heading";
      const title = document.createElement("h3");
      title.className = "log-title";
      title.textContent = `${entry.method} ${entry.url}`;
      const meta = document.createElement("p");
      meta.className = "log-meta";
      meta.textContent = `${entry.status ?? "No HTTP response"} · ${entry.elapsed} ms${entry.credentials ? ` · credentials: ${entry.credentials}` : ""}`;
      heading.append(title, meta);
      article.append(heading);
      article.append(section("Request body", entry.requestBody ?? "(no request body)"));
      article.append(section("Raw response body", entry.body ?? "(no response body)"));
      article.append(headerDetails("Request headers (Authorization omitted)", entry.requestHeaders || "(none)"));
      article.append(headerDetails("Response headers (browser-readable)", entry.responseHeaders || "(unavailable)"));
      if (entry.error) {
        const error = section("Network / CORS error", entry.error);
        error.className += " log-error";
        article.append(error);
      }
      elements.output.append(article);
    }
  }

  function record(entry) {
    state.entries.push(entry);
    renderEntries();
  }

  function readableHeaders(headers) {
    const lines = [];
    if (headers?.forEach) headers.forEach((value, name) => lines.push(`${name}: ${value}`));
    return lines.sort().join("\n");
  }

  function visibleRequestHeaders(headers) {
    return Object.entries(headers)
      .filter(([name]) => name.toLowerCase() !== "authorization")
      .map(([name, value]) => `${name}: ${value}`)
      .sort()
      .join("\n");
  }

  async function send({ url, method, headers, body, credentials }) {
    const started = performance.now();
    const entry = {
      url,
      method,
      credentials,
      requestHeaders: visibleRequestHeaders(headers),
      requestBody: body ?? null,
      responseHeaders: "",
      status: null,
      body: null,
      error: "",
      elapsed: 0,
    };
    let response;
    try {
      response = await request(url, {
        method,
        headers,
        ...(body === undefined ? {} : { body }),
        ...(credentials ? { credentials } : {}),
        cache: "no-store",
      });
    } catch (error) {
      entry.elapsed = Math.round(performance.now() - started);
      entry.error = error instanceof Error ? error.message : String(error);
      record(entry);
      setStatus(`Network/CORS error: ${entry.error}. See the request output below.`);
      return null;
    }
    entry.status = `HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}`;
    entry.responseHeaders = readableHeaders(response.headers);
    try {
      entry.body = await response.text();
    } catch (error) {
      entry.error = `Could not read response body: ${error instanceof Error ? error.message : String(error)}`;
    }
    entry.elapsed = Math.round(performance.now() - started);
    record(entry);
    return { response, body: entry.body ?? "" };
  }

  function clearContinueLink() {
    elements["continue-link"].hidden = true;
    elements["continue-link"].removeAttribute("href");
  }

  function validAuthorizationURL(value) {
    try {
      const url = new URL(value);
      return url.origin === "https://github.com"
        && url.pathname === "/login/oauth/authorize"
        && !url.username
        && !url.password;
    } catch {
      return false;
    }
  }

  async function connect() {
    const result = await send({
      url: `${MEDIATOR}/oauth/github/start`,
      method: "POST",
      headers: POST_HEADERS,
      body: "{}",
      credentials: "include",
    });
    if (!result) return;
    if (!result.response.ok) {
      setStatus(`GitHub start failed (${result.response.status}). See the response below.`);
      return;
    }
    let payload;
    try {
      payload = JSON.parse(result.body);
    } catch {
      setStatus("The start response was not valid JSON. See the raw response below.");
      return;
    }
    if (!payload || typeof payload !== "object"
      || typeof payload.authorization_url !== "string"
      || !validAuthorizationURL(payload.authorization_url)) {
      setStatus("The mediator returned an unexpected authorization URL; it was not opened.");
      return;
    }
    elements["continue-link"].href = payload.authorization_url;
    elements["continue-link"].hidden = false;
    setStatus("Authorization URL ready. Inspect the start response, then continue to GitHub. Output is not kept after navigation.");
  }

  async function getToken() {
    setStatus("Requesting a GitHub access token from the local mediator…");
    const result = await send({
      url: `${MEDIATOR}/oauth/github/token`,
      method: "POST",
      headers: POST_HEADERS,
      body: "{}",
      credentials: "include",
    });
    if (!result) return false;
    if (!result.response.ok) {
      setStatus(`Token request failed (${result.response.status}). See the response below.`);
      return false;
    }
    let payload;
    try {
      payload = JSON.parse(result.body);
    } catch {
      setStatus("The token response was not valid JSON. See the raw response below.");
      return false;
    }
    if (!payload || typeof payload !== "object"
      || typeof payload.access_token !== "string"
      || payload.access_token.length === 0) {
      setStatus("The token response did not contain an access token.");
      return false;
    }
    state.token = payload.access_token;
    elements["account-name"].textContent = "Token available in memory";
    elements["account-login"].textContent = "Fetch your GitHub profile to confirm the connection.";
    setStatus("Access token received and held in memory only. Fetch the profile to verify it.");
    return true;
  }

  async function fetchProfile() {
    if (!state.token) {
      setStatus("Get a token first. No token is stored between page loads.");
      return;
    }
    setStatus("Fetching the authenticated GitHub profile…");
    const result = await send({
      url: GITHUB_USER,
      method: "GET",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${state.token}`,
        "X-GitHub-Api-Version": "2022-11-28",
      },
      credentials: "omit",
    });
    if (!result) return;
    if (!result.response.ok) {
      setStatus(`GitHub profile request failed (${result.response.status}). See the response below.`);
      return;
    }
    let profile;
    try {
      profile = JSON.parse(result.body);
    } catch {
      setStatus("The GitHub profile response was not valid JSON. See the raw response below.");
      return;
    }
    if (!profile || typeof profile !== "object") {
      setStatus("The GitHub profile response was not a JSON object. See the raw response below.");
      return;
    }
    elements["account-name"].textContent = typeof profile.name === "string" && profile.name
      ? profile.name
      : (typeof profile.login === "string" ? profile.login : "GitHub account");
    elements["account-login"].textContent = typeof profile.login === "string" ? `@${profile.login}` : "Profile loaded";
    setStatus("GitHub profile loaded. The raw profile response is shown below.");
  }

  async function logout() {
    setStatus("Ending the local mediator session…");
    const result = await send({
      url: `${MEDIATOR}/session/logout`,
      method: "POST",
      headers: POST_HEADERS,
      body: "{}",
      credentials: "include",
    });
    if (!result) return;
    if (!result.response.ok) {
      setStatus(`Logout failed (${result.response.status}). Page state was kept; see the response below.`);
      return;
    }
    state.token = null;
    state.entries = [];
    elements["account-name"].textContent = "Not connected";
    elements["account-login"].textContent = "Connect to load your public profile.";
    clearContinueLink();
    renderEntries();
    setStatus("Logged out. The mediator session was cleared; this does not revoke the GitHub token.");
  }

  async function run(operation) {
    if (state.busy) return;
    clearContinueLink();
    setBusy(true);
    try {
      await operation();
    } catch (error) {
      setStatus(`Frontend error: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  elements["connect-button"].addEventListener("click", () => run(connect));
  elements["token-button"].addEventListener("click", () => run(getToken));
  elements["profile-button"].addEventListener("click", () => run(fetchProfile));
  elements["logout-button"].addEventListener("click", () => run(logout));
  elements["clear-button"].addEventListener("click", () => {
    if (state.busy) return;
    state.entries = [];
    clearContinueLink();
    renderEntries();
    setStatus(state.token
      ? "Output cleared. The access token remains in memory until logout or page close."
      : "Output cleared.");
  });

  const callbackComplete = new URL(location.href).searchParams.get("oauth") === "complete";
  let ready = Promise.resolve();
  if (callbackComplete) {
    const url = new URL(location.href);
    url.searchParams.delete("oauth");
    history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
    setStatus("Callback completed. Retrieving a token now; callback completion alone is not proof of success.");
    ready = run(async () => {
      if (await getToken()) await fetchProfile();
    });
  }
  return { ready };
}

if (typeof document !== "undefined" && document.getElementById("connect-button")) {
  createApp({ document });
}
