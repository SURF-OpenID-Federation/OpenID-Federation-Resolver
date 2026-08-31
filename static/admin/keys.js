function escapeHTML(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function jwkToPublicPEM(jwk) {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error("WebCrypto is not available in this browser");
  }

  let algorithm;
  if (jwk.kty === "EC") {
    const curveMap = { "P-256": "P-256", "P-384": "P-384", "P-521": "P-521" };
    const namedCurve = curveMap[jwk.crv || "P-256"];
    if (!namedCurve) throw new Error("Unsupported EC curve: " + (jwk.crv || "-"));
    algorithm = { name: "ECDSA", namedCurve: namedCurve };
  } else if (jwk.kty === "RSA") {
    algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  } else {
    throw new Error("Unsupported key type: " + (jwk.kty || "-"));
  }

  const key = await window.crypto.subtle.importKey("jwk", jwk, algorithm, true, ["verify"]);
  const spki = await window.crypto.subtle.exportKey("spki", key);
  const b64 = btoa(String.fromCharCode.apply(null, new Uint8Array(spki)));
  const lines = b64.match(/.{1,64}/g) || [];
  return "-----BEGIN PUBLIC KEY-----\n" + lines.join("\n") + "\n-----END PUBLIC KEY-----\n";
}

function downloadTextFile(filename, content) {
  const blob = new Blob([content], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function downloadKeyAsPEM(index) {
  const keys = window.AdminUI.currentJWKSKeys || [];
  const key = keys[index];
  if (!key) return;
  try {
    const pem = await jwkToPublicPEM(key);
    const pemEl = document.getElementById("pem-view-" + index);
    if (pemEl) pemEl.textContent = pem;
    const filename = (key.kid || "public-key") + ".pem";
    downloadTextFile(filename, pem);
  } catch (e) {
    window.AdminUI.showMsg("PEM export failed: " + e.message, "err");
  }
}

async function loadKeys() {
  const el = document.getElementById("keys-list");
  if (!el) return;
  try {
    const data = await window.AdminUI.apiFetch("/admin/v1/keys");
    const items = data.items || [];
    const keys = items
      .filter((k) => k.status === "active" || k.status === "retiring")
      .map((k) => Object.assign({}, k.public_jwk || {}, {
        kid: k.kid,
        alg: k.alg || (k.public_jwk && k.public_jwk.alg),
        kty: k.kty || (k.public_jwk && k.public_jwk.kty),
        _signing: !!k.signing,
        _status: k.status
      }));
    window.AdminUI.currentJWKSKeys = keys;
    if (!keys.length) {
      el.innerHTML = "<p class=\"empty\">No keys found.</p>";
    } else {
      el.innerHTML = keys.map((k, idx) => {
        const isActive = !!k._signing;
        const badge = isActive
          ? "<span class=\"badge active-key\">active signing key</span>"
          : "<span class=\"badge\" style=\"background:#e8eaed;color:#555\">previous</span>";
        return "<div class=\"card key-card\">"
          + "<div style=\"display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;margin-bottom:.4rem\">"
          + "<h3>" + escapeHTML(k.kid || "-") + "</h3>" + badge
          + "</div>"
          + "<div class=\"meta\">alg:&nbsp;" + escapeHTML(k.alg || "-") + "&nbsp;&nbsp;kty:&nbsp;" + escapeHTML(k.kty || "-") + (k.crv ? "&nbsp;&nbsp;crv:&nbsp;" + escapeHTML(k.crv) : "") + "</div>"
          + "<div class=\"key-actions\">"
          + "<button type=\"button\" class=\"btn\" style=\"background:var(--primary);color:#fff\" data-download-pem=\"" + idx + "\">Download PEM</button>"
          + (isActive ? "" : "<button type=\"button\" class=\"btn\" data-revoke-kid=\"" + escapeHTML(k.kid || "") + "\">Revoke</button>")
          + "</div>"
          + "<pre id=\"pem-view-" + idx + "\" class=\"key-pem\"></pre>"
          + "</div>";
      }).join("");

      el.querySelectorAll("[data-download-pem]").forEach((btn) => {
        btn.addEventListener("click", function() {
          downloadKeyAsPEM(Number(btn.getAttribute("data-download-pem")));
        });
      });
      el.querySelectorAll("[data-revoke-kid]").forEach((btn) => {
        btn.addEventListener("click", function() {
          revokeKey(btn.getAttribute("data-revoke-kid"));
        });
      });
    }

    const hist = items.filter((k) => k.status === "revoked" || k.status === "retired");
    if (hist.length) {
      el.insertAdjacentHTML("beforeend", "<h3 style=\"margin-top:1.5rem\">Historical keys</h3>" + hist.map((h) => {
        const status = h.status || "revoked";
        return "<div class=\"card key-card\">"
          + "<div class=\"card-head\">"
          + "<h3>" + escapeHTML(h.kid || "-") + "</h3>"
          + "<span class=\"badge\">" + escapeHTML(status) + "</span>"
          + "<button type=\"button\" class=\"btn icon-btn\" title=\"Purge from historical keys\" aria-label=\"Purge from historical keys\" data-purge-kid=\"" + escapeHTML(h.kid || "") + "\">"
          + "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">"
          + "<polyline points=\"3 6 5 6 21 6\"/><path d=\"M19 6l-1 14H6L5 6\"/><path d=\"M10 11v6\"/><path d=\"M14 11v6\"/><path d=\"M9 6V4h6v2\"/>"
          + "</svg></button>"
          + "</div>"
          + "</div>";
      }).join(""));
      el.querySelectorAll("[data-purge-kid]").forEach((btn) => {
        btn.addEventListener("click", function() {
          purgeHistoricalKey(btn.getAttribute("data-purge-kid"));
        });
      });
    }
  } catch (e) {
    el.innerHTML = "<p class=\"empty\">Error: " + escapeHTML(e.message) + "</p>";
  }
}

async function revokeKey(kid) {
  if (!kid) return;
  if (!confirm("Revoke key " + kid + "?\n\nSigning with this kid stops. The last remaining signing key cannot be deleted.")) return;
  try {
    await window.AdminUI.apiFetch(window.AdminUI.adminKeyPath(kid), { method: "DELETE" });
    window.AdminUI.showMsg("Key revoked: " + kid, "ok");
    loadKeys();
  } catch (e) {
    window.AdminUI.showMsg("Revoke failed: " + e.message, "err");
  }
}

async function purgeHistoricalKey(kid) {
  if (!kid) return;
  if (!confirm("Purge historical key " + kid + "?\n\nThis does not change the active signing key.")) return;
  try {
    await window.AdminUI.apiFetch(window.AdminUI.adminKeyPath(kid), { method: "DELETE" });
    window.AdminUI.showMsg("Purged historical key: " + kid, "ok");
    loadKeys();
  } catch (e) {
    window.AdminUI.showMsg("Purge failed: " + e.message, "err");
  }
}

async function rotateKey() {
  if (!confirm("Generate a new signing key?\n\nThe previous key stays in the JWKS during the transition window so already-issued resolve responses remain verifiable.")) return;
  try {
    const data = await window.AdminUI.apiFetch("/admin/v1/keys", {
      method: "POST",
      body: JSON.stringify({ generate: { alg: "ES256" } })
    });
    window.AdminUI.showMsg("Key rotated — new active kid: " + (data.kid || "-"), "ok");
    loadKeys();
  } catch (e) {
    window.AdminUI.showMsg("Rotation failed: " + e.message, "err");
  }
}
