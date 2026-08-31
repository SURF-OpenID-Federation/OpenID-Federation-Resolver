function fmtTS(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString();
}

function tokenBadge(status) {
  if (status === "active") return "<span class=\"badge approved\">active</span>";
  if (status === "revoked") return "<span class=\"badge denied\">revoked</span>";
  return "<span class=\"badge pending\">expired</span>";
}

async function loadTokens() {
  const el = document.getElementById("tokens-list");
  if (!el) return;
  try {
    const data = await window.AdminUI.apiFetch("/api/v1/tokens");
    const rows = data.tokens || [];
    const notices = [];
    if (data.env_api_key_set) {
      notices.push("<p class=\"meta\" style=\"margin-bottom:.5rem;color:#856404\">Legacy ENV API_KEY is set. Prefer PATs for day-2 operations; minting keys still requires the ENV key.</p>");
    }
    if (!rows.length) {
      el.innerHTML = notices.join("") + "<p class=\"empty\">No API keys yet.</p>";
      return;
    }
    el.innerHTML = notices.join("") + rows.map((t) => {
      const warn = t.unused_warn ? "<div class=\"meta\" style=\"color:#856404\">Unused for extended period.</div>" : "";
      return "<div class=\"card\">"
        + "<div style=\"display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;margin-bottom:.4rem\">"
        + "<h3>" + escapeHTML(t.name || t.id) + "</h3>"
        + tokenBadge(t.status)
        + "</div>"
        + "<div class=\"meta\">prefix: " + escapeHTML(t.prefix || "-")
        + "<br>scopes: " + escapeHTML(((t.scopes || []).join(", ")) || "-")
        + "<br>created: " + fmtTS(t.created_at)
        + "<br>expires: " + fmtTS(t.expires_at)
        + "<br>last used: " + fmtTS(t.last_used_at)
        + "</div>"
        + warn
        + (t.status === "active"
            ? "<div class=\"actions\"><button type=\"button\" class=\"btn deny\" onclick=\"revokeToken('" + escapeHTML(t.id) + "')\">Revoke</button></div>"
            : "")
        + "</div>";
    }).join("");
  } catch (e) {
    el.innerHTML = "<p class=\"empty\">Error: " + escapeHTML(e.message) + "</p>";
  }
}

async function createToken() {
  const nameEl = document.getElementById("patName");
  const daysEl = document.getElementById("patDays");
  const secretEl = document.getElementById("patSecret");
  const name = (nameEl ? nameEl.value : "").trim();
  const days = Number(daysEl ? daysEl.value : 90);
  if (!name) {
    window.AdminUI.showMsg("Token name is required.", "err");
    return;
  }
  try {
    const data = await window.AdminUI.apiFetch("/api/v1/tokens", {
      method: "POST",
      body: JSON.stringify({ name: name, ttl_days: days })
    });
    if (secretEl) {
      secretEl.style.display = "block";
      secretEl.textContent = data.token || "";
    }
    window.AdminUI.showMsg("API key created. Copy the secret now.", "ok");
    if (nameEl) nameEl.value = "";
    loadTokens();
  } catch (e) {
    window.AdminUI.showMsg("Error: " + e.message, "err");
  }
}

async function revokeToken(id) {
  if (!window.confirm("Revoke this API key?")) return;
  try {
    await window.AdminUI.apiFetch("/api/v1/tokens/" + encodeURIComponent(id), { method: "DELETE" });
    window.AdminUI.showMsg("API key revoked.", "ok");
    loadTokens();
  } catch (e) {
    window.AdminUI.showMsg("Error: " + e.message, "err");
  }
}
