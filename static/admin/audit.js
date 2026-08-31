function auditEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function auditFmtTS(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString();
}

function auditStatusBadge(status) {
  const n = Number(status);
  if (n >= 200 && n < 300) return "<span class=\"badge approved\">" + n + "</span>";
  if (n >= 400) return "<span class=\"badge denied\">" + n + "</span>";
  return "<span class=\"badge\">" + auditEscape(status || "-") + "</span>";
}

let auditCursor = "";
let auditRows = [];

function renderAuditList() {
  const el = document.getElementById("audit-list");
  if (!el) return;
  if (!auditRows.length) {
    el.innerHTML = "<p class=\"empty\">No audit events yet.</p>";
    return;
  }
  el.innerHTML = auditRows.map((e) => {
    return "<div class=\"card audit-card\">"
      + "<div class=\"card-head\">"
      + "<h3>" + auditEscape(e.action || e.method || "event") + "</h3>"
      + auditStatusBadge(e.status)
      + "</div>"
      + "<div class=\"meta\">"
      + auditEscape(auditFmtTS(e.ts))
      + (e.actor ? "<br>actor: " + auditEscape(e.actor) : "")
      + (e.auth ? "<br>auth: " + auditEscape(e.auth) : "")
      + (e.token ? " &nbsp; token: " + auditEscape(e.token) : "")
      + "<br>" + auditEscape(e.method || "") + " " + auditEscape(e.path || "")
      + "</div>"
      + "</div>";
  }).join("");
}

async function loadAudit(append) {
  const el = document.getElementById("audit-list");
  const more = document.getElementById("audit-more");
  if (!el) return;
  try {
    const q = new URLSearchParams();
    q.set("limit", "50");
    if (append && auditCursor) q.set("cursor", auditCursor);
    const data = await window.AdminUI.apiFetch("/admin/v1/audit?" + q.toString());
    const items = data.items || [];
    if (!append) auditRows = [];
    auditRows = auditRows.concat(items);
    auditCursor = data.next || "";
    if (more) more.style.display = auditCursor ? "inline-block" : "none";
    renderAuditList();
  } catch (e) {
    el.innerHTML = "<p class=\"empty\">Error: " + auditEscape(e.message) + "</p>";
    if (more) more.style.display = "none";
  }
}
