(function() {
  const bodyData = document.body ? document.body.dataset : {};
  const config = {
    serverOIDC: String(bodyData.serverOidc || "").toLowerCase() === "true",
    entityID: String(bodyData.entityId || ""),
    loginUrl: String(bodyData.loginUrl || "")
  };

  function apiKey() {
    const input = document.getElementById("apiKey");
    return input ? input.value.trim() : "";
  }

  function showMsg(text, type) {
    const el = document.getElementById("msg");
    if (!el) return;
    el.textContent = text;
    el.className = "message " + type;
    el.style.display = "block";
    setTimeout(() => { el.style.display = "none"; }, 5000);
  }

  function errorMessage(payload, status) {
    if (!payload || typeof payload !== "object") return "HTTP " + status;
    return payload.detail || payload.error_description || payload.error || payload.title || ("HTTP " + status);
  }

  function redirectToAdminLogin() {
    const custom = config.loginUrl;
    let target;
    if (custom) {
      target = custom.indexOf("{return_url}") >= 0
        ? custom.replace("{return_url}", encodeURIComponent(window.location.href))
        : custom;
    } else {
      target = "/admin/login?rd=" + encodeURIComponent(window.location.href);
    }
    window.location.href = target;
  }

  async function apiFetch(path, opts = {}) {
    const h = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (!config.serverOIDC) {
      const key = apiKey();
      if (key) h["X-API-Key"] = key;
    }
    opts.headers = h;
    if (!opts.credentials) opts.credentials = "same-origin";
    const r = await fetch(path, opts);
    if (r.status === 401 && config.serverOIDC) {
      redirectToAdminLogin();
      throw new Error("Re-authentication required");
    }
    const text = await r.text();
    let data = {};
    if (text) {
      try { data = JSON.parse(text); } catch (e) { data = { raw: text }; }
    }
    if (!r.ok) {
      throw new Error(errorMessage(data, r.status));
    }
    if (r.status === 204) return {};
    if (data && typeof data === "object" && !Array.isArray(data)) {
      const etag = r.headers.get("ETag");
      if (etag) data._etag = etag;
    }
    return data;
  }

  function adminKeyPath(kid) {
    return "/admin/v1/keys/" + encodeURIComponent(kid);
  }

  window.AdminUI = {
    config: config,
    lsKey: "oidf_api_key_" + btoa(config.entityID || "resolver"),
    apiKey: apiKey,
    showMsg: showMsg,
    apiFetch: apiFetch,
    redirectToAdminLogin: redirectToAdminLogin,
    adminKeyPath: adminKeyPath
  };
})();
