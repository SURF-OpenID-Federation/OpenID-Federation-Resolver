function linesToList(text) {
  return String(text || "")
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function listToLines(value) {
  if (!value) return "";
  if (Array.isArray(value)) return value.join("\n");
  return String(value);
}

function federationEntity(doc) {
  const md = doc && doc.metadata ? doc.metadata : {};
  return md.federation_entity || {};
}

async function loadConfig() {
  const form = document.getElementById("config-form");
  if (!form) return;
  try {
    const doc = await window.AdminUI.apiFetch("/admin/v1/configuration");
    window.AdminUI.configDoc = doc;
    const fed = federationEntity(doc);
    document.getElementById("cfgEntityId").value = doc.entity_id || "";
    document.getElementById("cfgOrgName").value = fed.organization_name || "";
    document.getElementById("cfgOrgURI").value = fed.organization_uri || "";
    document.getElementById("cfgLogoURI").value = fed.logo_uri || "";
    document.getElementById("cfgContacts").value = listToLines(fed.contacts);
    document.getElementById("cfgAuthorityHints").value = listToLines(doc.authority_hints);
    document.getElementById("cfgTrustAnchors").value = listToLines(doc.trust_anchor_hints);
    document.getElementById("cfgLifetime").value = doc.lifetime || 86400;
  } catch (e) {
    window.AdminUI.showMsg("Failed to load configuration: " + e.message, "err");
  }
}

async function saveConfig(ev) {
  if (ev) ev.preventDefault();
  const current = window.AdminUI.configDoc || {};
  const metadata = Object.assign({}, current.metadata || {});
  const fed = Object.assign({}, federationEntity(current));
  fed.organization_name = document.getElementById("cfgOrgName").value.trim();
  const orgURI = document.getElementById("cfgOrgURI").value.trim();
  const logoURI = document.getElementById("cfgLogoURI").value.trim();
  if (orgURI) fed.organization_uri = orgURI; else delete fed.organization_uri;
  if (logoURI) fed.logo_uri = logoURI; else delete fed.logo_uri;
  const contacts = linesToList(document.getElementById("cfgContacts").value);
  if (contacts.length) fed.contacts = contacts; else delete fed.contacts;
  metadata.federation_entity = fed;
  const patch = {
    lifetime: Number(document.getElementById("cfgLifetime").value) || 86400,
    authority_hints: linesToList(document.getElementById("cfgAuthorityHints").value),
    trust_anchor_hints: linesToList(document.getElementById("cfgTrustAnchors").value),
    metadata: metadata
  };
  const headers = {};
  if (current._etag) headers["If-Match"] = current._etag;
  try {
    const doc = await window.AdminUI.apiFetch("/admin/v1/configuration", {
      method: "PATCH",
      headers: headers,
      body: JSON.stringify(patch)
    });
    window.AdminUI.configDoc = doc;
    window.AdminUI.showMsg("Configuration saved.", "ok");
    loadConfig();
    loadTrustAnchors();
  } catch (e) {
    window.AdminUI.showMsg("Save failed: " + e.message, "err");
  }
}

async function loadTrustAnchors() {
  const configuredEl = document.getElementById("configured-tas");
  const registeredEl = document.getElementById("registered-tas");
  if (configuredEl) {
    try {
      const data = await window.AdminUI.apiFetch("/api/v1/trust-anchors");
      const tas = data.trust_anchors || [];
      if (!tas.length) {
        configuredEl.innerHTML = "<p class=\"empty\">No configured trust anchors.</p>";
      } else {
        configuredEl.innerHTML = tas.map((id) =>
          "<div class=\"card\"><h3>" + escapeHTML(id) + "</h3></div>"
        ).join("");
      }
    } catch (e) {
      configuredEl.innerHTML = "<p class=\"empty\">Error: " + escapeHTML(e.message) + "</p>";
    }
  }
  if (registeredEl) {
    try {
      const data = await window.AdminUI.apiFetch("/api/v1/registered-trust-anchors");
      const anchors = data.registered_trust_anchors || {};
      const ids = Object.keys(anchors);
      if (!ids.length) {
        registeredEl.innerHTML = "<p class=\"empty\">No signing authorizations registered.</p>";
        return;
      }
      registeredEl.innerHTML = ids.map((id) => {
        const rec = anchors[id] || {};
        return "<div class=\"card\">"
          + "<h3>" + escapeHTML(id) + "</h3>"
          + "<div class=\"meta\">expires: " + escapeHTML(rec.expires_at || "—") + "</div>"
          + "<div class=\"actions\"><button type=\"button\" class=\"btn deny\" data-unreg=\"" + escapeHTML(id) + "\">Unregister</button></div>"
          + "</div>";
      }).join("");
      registeredEl.querySelectorAll("[data-unreg]").forEach((btn) => {
        btn.addEventListener("click", function() {
          unregisterTrustAnchor(btn.getAttribute("data-unreg"));
        });
      });
    } catch (e) {
      registeredEl.innerHTML = "<p class=\"empty\">Error: " + escapeHTML(e.message) + "</p>";
    }
  }
}

async function unregisterTrustAnchor(entityID) {
  if (!entityID) return;
  if (!confirm("Unregister signing authorization for " + entityID + "?")) return;
  const taKey = (document.getElementById("taApiKey") || {}).value || "";
  try {
    const headers = { "Content-Type": "application/json" };
    if (taKey.trim()) headers["X-API-Key"] = taKey.trim();
    const r = await fetch("/api/v1/registered-trust-anchors/" + encodeURIComponent(entityID), {
      method: "DELETE",
      headers: headers,
      credentials: "same-origin"
    });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      throw new Error(e.error_description || e.error || e.details || ("HTTP " + r.status));
    }
    window.AdminUI.showMsg("Unregistered " + entityID, "ok");
    loadTrustAnchors();
  } catch (e) {
    window.AdminUI.showMsg("Unregister failed: " + e.message, "err");
  }
}

async function loadCache() {
  const el = document.getElementById("cache-stats");
  if (!el) return;
  try {
    const data = await window.AdminUI.apiFetch("/admin/v1/cache/stats");
    el.textContent = "entity_cache_size=" + (data.entity_cache_size ?? "—")
      + "  chain_cache_size=" + (data.chain_cache_size ?? "—");
  } catch (e) {
    el.textContent = "Error: " + e.message;
  }
}

async function clearCache(kind) {
  const urls = {
    all: "/admin/v1/cache/clear-all",
    entities: "/admin/v1/cache/clear-entities",
    chains: "/admin/v1/cache/clear-chains"
  };
  const path = urls[kind];
  if (!path) return;
  if (!confirm("Clear " + kind + " cache?")) return;
  try {
    await window.AdminUI.apiFetch(path, { method: "POST" });
    window.AdminUI.showMsg("Cleared " + kind + " cache.", "ok");
    loadCache();
  } catch (e) {
    window.AdminUI.showMsg("Clear failed: " + e.message, "err");
  }
}
