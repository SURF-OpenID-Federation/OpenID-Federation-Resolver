const ADMIN_LOGOFF_URL = "/admin/logoff";

function adminLogoff() {
  window.location.href = ADMIN_LOGOFF_URL;
}

function loadAll() {
  return Promise.all([
    loadConfig(),
    loadKeys(),
    loadTokens(),
    loadTrustAnchors(),
    loadCache()
  ]);
}

function saveAndLoad() {
  const key = window.AdminUI.apiKey();
  if (key) localStorage.setItem(window.AdminUI.lsKey, key);
  loadAll();
}

function clearKey() {
  localStorage.removeItem(window.AdminUI.lsKey);
  const input = document.getElementById("apiKey");
  if (input) input.value = "";
  window.AdminUI.showMsg("API key cleared.", "ok");
}

function switchTab(el, name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
  el.classList.add("active");
  document.getElementById("tab-" + name).classList.add("active");
}

async function loadWhoami() {
  const display = document.getElementById("user-display");
  const banner = document.getElementById("user-banner");
  if (!display || !banner) return;
  try {
    if (display.textContent.trim() !== "") {
      banner.style.display = "flex";
      return;
    }
    let r = await fetch("/api/v1/whoami", { credentials: "same-origin" });
    if (r.status === 401) {
      if (window.AdminUI.config.serverOIDC) {
        window.AdminUI.redirectToAdminLogin();
        return;
      }
      const k = window.AdminUI.apiKey();
      if (k) {
        r = await fetch("/api/v1/whoami", {
          headers: { "X-API-Key": k },
          credentials: "same-origin"
        });
      }
    }
    if (!r.ok) return;
    const data = await r.json();
    if (data.auth_method === "api_key" || data.auth_method === "pat") return;
    let label = data.display_name;
    if (!label) label = "Signed in";
    display.textContent = label;
    banner.style.display = "flex";
  } catch (e) {}
}

document.addEventListener("DOMContentLoaded", function() {
  const saved = localStorage.getItem(window.AdminUI.lsKey);
  if (window.AdminUI.config.serverOIDC) {
    loadAll();
  } else if (saved) {
    const input = document.getElementById("apiKey");
    if (input) input.value = saved;
    loadAll();
  } else {
    loadAll();
  }
  loadWhoami();
});
