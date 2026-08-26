(function () {
    const THEME_KEY = "resolver-console-theme";
    const API_KEY_STORAGE = "resolver-api-key";
    const POLL_MS = 2000;
    const MAX_POINTS = 90;

    const state = {
        view: "ops",
        paused: false,
        last: null,
        history: [],
        swaggerLoaded: false,
        operatorRequired: false,
    };

    const $ = (id) => document.getElementById(id);
    const PLACEHOLDER_ENTITY_ID = "https://resolver.example.org";

    function displayEntityID(data) {
        const configured = String((data && data.entity_id) || "")
            .trim()
            .replace(/\/$/, "");
        if (configured && configured !== PLACEHOLDER_ENTITY_ID) return configured;
        return window.location.origin;
    }

    function setBrandSub(data) {
        const el = $("brandSub");
        if (!el) return;
        const id = displayEntityID(data);
        el.textContent = id;
        el.title = id;
    }

    function apiFetch(url, opts) {
        const headers = Object.assign({}, (opts && opts.headers) || {});
        const key = storedApiKey();
        if (key && !headers.Authorization && !headers["X-API-Key"]) {
            headers.Authorization = "Bearer " + key;
        }
        const next = Object.assign({ cache: "no-store" }, opts || {}, { headers: headers });
        return fetch(url, next).then((res) => {
            const method = (next.method || "GET").toUpperCase();
            if (res.status === 401 && state.operatorRequired && method !== "GET") {
                showLock("That key was rejected.");
            }
            return res;
        });
    }

    function storedApiKey() {
        try {
            return sessionStorage.getItem(API_KEY_STORAGE) || "";
        } catch (err) {
            return "";
        }
    }

    function setStoredApiKey(value) {
        try {
            if (value) sessionStorage.setItem(API_KEY_STORAGE, value);
            else sessionStorage.removeItem(API_KEY_STORAGE);
        } catch (err) {
            /* ignore quota / private mode */
        }
        updateSignOut();
    }

    function updateSignOut() {
        const btn = $("signOutBtn");
        if (!btn) return;
        btn.hidden = !storedApiKey();
    }

    function showLock(errorText) {
        const overlay = $("lockOverlay");
        overlay.hidden = false;
        overlay.classList.add("is-open");
        const err = $("lockError");
        if (errorText) {
            err.hidden = false;
            err.textContent = errorText;
        } else {
            err.hidden = true;
        }
        const input = $("apiKeyInput");
        if (input && document.activeElement !== input) input.focus();
    }

    function hideLock() {
        $("lockOverlay").hidden = true;
        $("lockOverlay").classList.remove("is-open");
        $("lockError").hidden = true;
    }

    async function checkAuth() {
        try {
            const res = await fetch("/api/v1/auth/status", { cache: "no-store" });
            if (!res.ok) return;
            const data = await res.json();
            state.operatorRequired = !!data.operator_required;
            updateSignOut();
        } catch (err) {
            /* first poll will surface connectivity issues */
        }
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme === "light" ? "light" : "dark");
        localStorage.setItem(THEME_KEY, theme === "light" ? "light" : "dark");
        Object.values(charts).forEach((c) => c && c.draw());
    }

    function initTheme() {
        const stored = localStorage.getItem(THEME_KEY);
        applyTheme(stored === "light" ? "light" : "dark");
    }

    function cssVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    function formatUptime(seconds) {
        const s = Math.max(0, Math.floor(seconds || 0));
        const d = Math.floor(s / 86400);
        const h = Math.floor((s % 86400) / 3600);
        const m = Math.floor((s % 3600) / 60);
        if (d > 0) return d + "d " + h + "h";
        if (h > 0) return h + "h " + m + "m";
        if (m > 0) return m + "m " + (s % 60) + "s";
        return s + "s";
    }

    function formatNumber(n, digits) {
        if (n == null || Number.isNaN(n)) return "—";
        const d = digits == null ? (Math.abs(n) >= 10 ? 1 : 2) : digits;
        return Number(n).toLocaleString(undefined, { maximumFractionDigits: d, minimumFractionDigits: 0 });
    }

    function formatPct(n) {
        if (n == null || Number.isNaN(n)) return "—";
        return (n * 100).toFixed(1) + "%";
    }

    function relativeTime(iso) {
        if (!iso) return "";
        const t = new Date(iso).getTime();
        const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
        if (sec < 5) return "just now";
        return sec + "s ago";
    }

    function rate(curr, prev, keyPath, dt) {
        if (!prev || dt <= 0) return 0;
        const a = getPath(curr, keyPath);
        const b = getPath(prev, keyPath);
        return Math.max(0, (a - b) / dt);
    }

    function getPath(obj, path) {
        return path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj) || 0;
    }

    function createChart(canvas, series) {
        const ctx = canvas.getContext("2d");
        const chart = {
            series: series,
            draw: function () {
                const dpr = window.devicePixelRatio || 1;
                const w = canvas.clientWidth || 480;
                const h = canvas.clientHeight || 180;
                canvas.width = Math.floor(w * dpr);
                canvas.height = Math.floor(h * dpr);
                ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
                ctx.clearRect(0, 0, w, h);

                const pad = { l: 42, r: 12, t: 10, b: 22 };
                const plotW = w - pad.l - pad.r;
                const plotH = h - pad.t - pad.b;
                const points = state.history;
                ctx.strokeStyle = cssVar("--chart-grid");
                ctx.lineWidth = 1;
                for (let i = 0; i <= 4; i++) {
                    const y = pad.t + (plotH * i) / 4;
                    ctx.beginPath();
                    ctx.moveTo(pad.l, y);
                    ctx.lineTo(w - pad.r, y);
                    ctx.stroke();
                }

                let max = 0;
                series.forEach((s) => {
                    points.forEach((p) => {
                        const v = p.values[s.key] || 0;
                        if (v > max) max = v;
                    });
                });
                if (max <= 0) max = 1;

                ctx.fillStyle = cssVar("--muted");
                ctx.font = "11px " + cssVar("--font");
                ctx.textAlign = "right";
                ctx.textBaseline = "middle";
                for (let i = 0; i <= 4; i++) {
                    const v = max * (1 - i / 4);
                    const y = pad.t + (plotH * i) / 4;
                    ctx.fillText(formatAxis(v), pad.l - 6, y);
                }

                const n = Math.max(points.length - 1, 1);
                series.forEach((s) => {
                    ctx.beginPath();
                    ctx.strokeStyle = s.color();
                    ctx.lineWidth = 1.6;
                    points.forEach((p, i) => {
                        const x = pad.l + (plotW * i) / n;
                        const y = pad.t + plotH * (1 - (p.values[s.key] || 0) / max);
                        if (i === 0) ctx.moveTo(x, y);
                        else ctx.lineTo(x, y);
                    });
                    ctx.stroke();
                });

                ctx.textAlign = "left";
                ctx.textBaseline = "top";
                let lx = pad.l;
                const ly = h - 16;
                series.forEach((s) => {
                    ctx.fillStyle = s.color();
                    ctx.fillRect(lx, ly, 10, 10);
                    ctx.fillStyle = cssVar("--muted");
                    ctx.fillText(s.label, lx + 14, ly - 1);
                    lx += ctx.measureText(s.label).width + 32;
                });
            },
        };
        return chart;
    }

    function formatAxis(v) {
        if (v >= 100) return v.toFixed(0);
        if (v >= 10) return v.toFixed(1);
        return v.toFixed(2);
    }

    const charts = {};

    function initCharts() {
        charts.throughput = createChart($("chartThroughput"), [
            { key: "rps", label: "req/s", color: () => cssVar("--accent") },
            { key: "okps", label: "2xx/s", color: () => cssVar("--positive") },
            { key: "failps", label: "4xx+5xx/s", color: () => cssVar("--negative") },
        ]);
        charts.resolutions = createChart($("chartResolutions"), [
            { key: "entityOk", label: "entity ok/s", color: () => cssVar("--positive") },
            { key: "entityErr", label: "entity fail/s", color: () => cssVar("--negative") },
            { key: "chainOk", label: "chain ok/s", color: () => cssVar("--accent") },
        ]);
        charts.cache = createChart($("chartCache"), [
            { key: "hitps", label: "hits/s", color: () => cssVar("--positive") },
            { key: "missps", label: "misses/s", color: () => cssVar("--warning") },
            { key: "cacheSize", label: "entries", color: () => cssVar("--accent") },
        ]);
        charts.concurrency = createChart($("chartConcurrency"), [
            { key: "active", label: "HTTP conns", color: () => cssVar("--accent") },
            { key: "inflight", label: "resolves", color: () => cssVar("--warning") },
        ]);
    }

    function setView(name) {
        state.view = name;
        document.querySelectorAll(".tabs .tab").forEach((btn) => {
            const on = btn.getAttribute("data-view") === name;
            btn.classList.toggle("is-active", on);
            btn.setAttribute("aria-selected", on ? "true" : "false");
        });
        document.querySelectorAll(".view").forEach((el) => {
            el.classList.toggle("is-active", el.id === "view-" + name);
        });
        if (name === "api") loadSwagger();
        if (name === "inspect") refreshCacheLists();
        if (name === "ops") Object.values(charts).forEach((c) => c && c.draw());
    }

    function loadSwagger() {
        const frame = $("swaggerFrame");
        if (!state.swaggerLoaded) {
            frame.src = "/api/v1/docs";
            state.swaggerLoaded = true;
        }
    }

    async function poll() {
        if (state.paused) return;
        if (state.operatorRequired && !storedApiKey()) return;
        try {
            const res = await apiFetch("/api/v1/ops");
            if (res.status === 401) {
                $("liveLabel").textContent = "Locked";
                return;
            }
            if (!res.ok) throw new Error("ops " + res.status);
            const data = await res.json();
            applySnapshot(data);
            $("livePill").classList.remove("is-error");
            hideLock();
        } catch (err) {
            $("liveLabel").textContent = "Unreachable";
            $("livePill").classList.add("is-error");
        }
    }

    function applySnapshot(data) {
        const metrics = data.metrics || {};
        const http = metrics.http || {};
        const res = metrics.resolutions || {};
        const cache = metrics.cache || {};
        const now = Date.now();
        const prev = state.last;
        const dt = prev ? Math.max((now - prev.t) / 1000, 0.001) : 0;

        const sample = {
            t: now,
            payload: data,
            values: {
                rps: rate(http, prev && prev.http, "requests_total", dt),
                okps: rate(http, prev && prev.http, "requests_2xx", dt),
                failps:
                    rate(http, prev && prev.http, "requests_4xx", dt) +
                    rate(http, prev && prev.http, "requests_5xx", dt),
                entityOk: rate(res, prev && prev.resolutions, "entity_success", dt),
                entityErr: rate(res, prev && prev.resolutions, "entity_error", dt),
                chainOk: rate(res, prev && prev.resolutions, "chain_success", dt),
                hitps: rate(cache, prev && prev.cache, "hits", dt),
                missps: rate(cache, prev && prev.cache, "misses", dt),
                cacheSize:
                    Number((data.cache && data.cache.entity_cache_size) || 0) +
                    Number((data.cache && data.cache.chain_cache_size) || 0),
                active: Number(metrics.active_connections || 0),
                inflight: Number(data.inflight_resolves || 0),
                errorsps: rate(metrics.errors || {}, prev && prev.errors, "total", dt),
            },
        };

        state.history.push(sample);
        if (state.history.length > MAX_POINTS) state.history.shift();
        state.last = {
            t: now,
            http: http,
            resolutions: res,
            cache: cache,
            errors: metrics.errors || {},
        };

        setBrandSub(data);
        $("kpiUptime").textContent = formatUptime(metrics.uptime_seconds);
        $("kpiUpdated").textContent = "Updated " + relativeTime(data.timestamp);
        $("kpiRps").textContent = formatNumber(sample.values.rps);
        $("kpiInflight").textContent =
            formatNumber(sample.values.active, 0) + " / " + formatNumber(sample.values.inflight, 0);
        $("kpiHitRatio").textContent = formatPct(cache.hit_ratio);
        $("kpiCacheHint").textContent =
            formatNumber(cache.hits, 0) + " hits · " + formatNumber(cache.misses, 0) + " misses";
        $("kpiFail").textContent = formatNumber(sample.values.errorsps + sample.values.failps);
        $("liveLabel").textContent = "Live";

        renderAnchors(data);
        renderErrors((metrics.errors && metrics.errors.by_type) || []);
        renderCacheTable(data);
        Object.values(charts).forEach((c) => c && c.draw());
    }

    const SHIELD_SVG =
        '<svg class="ta-shield" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">' +
        '<path fill="currentColor" d="M12 2.5l8 3.2v6.4c0 5-3.4 9.4-8 10.9-4.6-1.5-8-5.9-8-10.9V5.7L12 2.5z"/>' +
        '<path fill="none" stroke="var(--bg-elevated)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" d="M8.8 12.2l2.2 2.2 4.2-4.6"/>' +
        "</svg>";

    function registeredAnchorSet(data) {
        const raw = data.registered_trust_anchors;
        if (Array.isArray(raw)) return new Set(raw);
        return new Set();
    }

    function renderAnchors(data) {
        const list = $("anchorList");
        const configured = data.trust_anchors || [];
        const registered = registeredAnchorSet(data);
        $("taSummary").textContent =
            configured.length +
            " configured · " +
            registered.size +
            " registered for signing";
        const seen = new Set();
        const rows = [];
        configured.forEach((ta) => {
            seen.add(ta);
            rows.push(ta);
        });
        Array.from(registered)
            .sort()
            .forEach((ta) => {
                if (!seen.has(ta)) rows.push(ta);
            });
        if (!rows.length) {
            list.innerHTML = '<li class="muted">No trust anchors configured</li>';
        } else {
            list.innerHTML = rows
                .map((ta) => {
                    const signing = registered.has(ta);
                    const shield = signing
                        ? SHIELD_SVG + '<span class="ta-shield-label">registered for signing</span>'
                        : "";
                    return (
                        "<li" +
                        (signing ? ' class="is-signing"' : "") +
                        ' title="' +
                        (signing ? "Registered for signing" : "Configured") +
                        '">' +
                        shield +
                        '<span class="ta-id">' +
                        escapeHtml(ta) +
                        "</span></li>"
                    );
                })
                .join("");
        }
        const select = $("trustAnchor");
        const current = select.value;
        const options = ['<option value="">Any configured anchor</option>'].concat(
            rows.map((ta) => {
                const mark = registered.has(ta) ? "🛡 " : "";
                return (
                    '<option value="' +
                    escapeAttr(ta) +
                    '">' +
                    mark +
                    escapeHtml(ta) +
                    "</option>"
                );
            })
        );
        select.innerHTML = options.join("");
        if (current) select.value = current;
    }

    function renderErrors(rows) {
        const body = $("errorTable");
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="2" class="empty">No errors recorded</td></tr>';
            return;
        }
        rows.sort((a, b) => b.count - a.count);
        body.innerHTML = rows
            .map(
                (r) =>
                    "<tr><td>" +
                    escapeHtml(r.label) +
                    '</td><td class="num">' +
                    formatNumber(r.count, 0) +
                    "</td></tr>"
            )
            .join("");
    }

    function renderCacheTable(data) {
        const body = $("cacheTable");
        const byName = (data.metrics && data.metrics.cache && data.metrics.cache.by_name) || [];
        const sizes = data.cache || {};
        const rows = byName.length
            ? byName
            : [
                  { name: "entity_statements", size: sizes.entity_cache_size || 0, hits: 0, misses: 0 },
                  { name: "trust_chains", size: sizes.chain_cache_size || 0, hits: 0, misses: 0 },
              ];
        body.innerHTML = rows
            .map((r) => {
                const size =
                    r.name === "entity_statements"
                        ? sizes.entity_cache_size
                        : r.name === "trust_chains"
                          ? sizes.chain_cache_size
                          : r.name === "unresolvable_entities"
                            ? sizes.unresolvable_cache_size
                            : r.size;
                return (
                    "<tr><td>" +
                    escapeHtml(r.name) +
                    '</td><td class="num">' +
                    formatNumber(size, 0) +
                    '</td><td class="num">' +
                    formatNumber(r.hits, 0) +
                    '</td><td class="num">' +
                    formatNumber(r.misses, 0) +
                    "</td></tr>"
                );
            })
            .join("");
    }

    async function refreshCacheLists() {
        try {
            const [entitiesRes, chainsRes] = await Promise.all([
                apiFetch("/api/v1/cache/entities"),
                apiFetch("/api/v1/cache/chains"),
            ]);
            const entities = entitiesRes.ok ? await entitiesRes.json() : { cached_entities: [] };
            const chains = chainsRes.ok ? await chainsRes.json() : { cached_chains: [] };
            const ents = entities.cached_entities || [];
            const chs = chains.cached_chains || [];
            $("cachedEntityCount").textContent = ents.length + " entries";
            $("cachedChainCount").textContent = chs.length + " entries";
            $("cachedEntities").innerHTML = ents.length
                ? ents
                      .map((e) => {
                          const id = e.entity_id || e.subject || "";
                          return (
                              '<tr class="clickable" data-kind="cached-entity" data-id="' +
                              escapeAttr(id) +
                              '" data-ta="' +
                              escapeAttr(e.trust_anchor || "") +
                              '"><td>' +
                              escapeHtml(e.subject || id) +
                              "</td><td>" +
                              escapeHtml(e.issuer || "") +
                              "</td><td>" +
                              escapeHtml(formatTime(e.expires_at)) +
                              "</td></tr>"
                          );
                      })
                      .join("")
                : '<tr><td colspan="3" class="empty">Cache is empty</td></tr>';
            $("cachedChains").innerHTML = chs.length
                ? chs
                      .map((c) => {
                          const id = c.entity_id || "";
                          return (
                              '<tr class="clickable" data-kind="cached-chain" data-id="' +
                              escapeAttr(id) +
                              '"><td>' +
                              escapeHtml(id) +
                              "</td><td>" +
                              escapeHtml(c.trust_anchor || "") +
                              '</td><td class="num">' +
                              ((c.chain && c.chain.length) || 0) +
                              "</td><td>" +
                              escapeHtml(formatTime(c.expires_at)) +
                              "</td></tr>"
                          );
                      })
                      .join("")
                : '<tr><td colspan="4" class="empty">Cache is empty</td></tr>';
        } catch (err) {
            toast("Failed to load cache lists");
        }
    }

    function formatTime(value) {
        if (!value) return "";
        const d = new Date(value);
        if (Number.isNaN(d.getTime())) return String(value);
        return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
    }

    function entityIdValue() {
        return $("entityId").value.trim();
    }

    function trustAnchorValue() {
        return $("trustAnchor").value.trim();
    }

    function withQuery(url) {
        const ta = trustAnchorValue();
        const refresh = $("forceRefresh").checked;
        const params = [];
        if (ta) params.push("trust_anchor=" + encodeURIComponent(ta));
        if (refresh) params.push("force_refresh=true");
        return params.length ? url + "?" + params.join("&") : url;
    }

    async function runInspect(action, presetId, presetTa) {
        const entityId = presetId || entityIdValue();
        if (action !== "fedlist" && !entityId) {
            toast("Enter an entity identifier");
            return;
        }
        const ta = presetTa != null ? presetTa : trustAnchorValue();
        let url = "";
        let title = "";
        switch (action) {
            case "entity":
                url = withQuery("/api/v1/entity/" + encodeURIComponent(entityId));
                title = "Entity resolution";
                break;
            case "chain":
                url = withQuery("/api/v1/trust-chain/" + encodeURIComponent(entityId));
                title = "Trust chain";
                break;
            case "fedlist":
                if (!ta) {
                    toast("Select a trust anchor for the federation list");
                    return;
                }
                url = "/api/v1/federation_list?trust_anchor=" + encodeURIComponent(ta);
                title = "Federation list";
                break;
            case "cached-entity":
                url = "/api/v1/cache/entity/" + encodeURIComponent(entityId);
                if (ta) url += "?trust_anchor=" + encodeURIComponent(ta);
                title = "Cached entity";
                break;
            case "cached-chain":
                url = "/api/v1/cache/chain/" + encodeURIComponent(entityId);
                title = "Cached trust chain";
                break;
            default:
                return;
        }
        const started = performance.now();
        try {
            const res = await apiFetch(url);
            const ct = res.headers.get("content-type") || "";
            const text = await res.text();
            const elapsed = Math.round(performance.now() - started);
            openModal({
                title: title,
                meta: res.status + " · " + elapsed + " ms · " + (ct.split(";")[0] || "unknown"),
                ok: res.ok,
                contentType: ct,
                text: text,
            });
        } catch (err) {
            openModal({
                title: title || "Request failed",
                meta: "network error",
                ok: false,
                contentType: "text/plain",
                text: String(err),
            });
        }
    }

    function isJwt(text) {
        if (!text || text.length < 20) return false;
        const parts = text.trim().split(".");
        return parts.length === 3 && /^[A-Za-z0-9_-]+$/.test(parts[0]);
    }

    function decodeJwt(token) {
        const parts = token.trim().split(".");
        const decode = (seg) => {
            const b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
            const pad = b64 + "===".slice((b64.length + 3) % 4);
            const binary = atob(pad);
            const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
            return JSON.parse(new TextDecoder().decode(bytes));
        };
        return {
            header: decode(parts[0]),
            payload: decode(parts[1]),
            signature: parts[2],
        };
    }

    function parseBody(text, contentType) {
        const trimmed = (text || "").trim();
        if (!trimmed) return { empty: true };
        if ((contentType || "").includes("json") || trimmed.charAt(0) === "{" || trimmed.charAt(0) === "[") {
            try {
                return { json: JSON.parse(trimmed) };
            } catch (err) {
                return { text: trimmed, parseError: String(err) };
            }
        }
        if (isJwt(trimmed)) {
            try {
                return { jwt: decodeJwt(trimmed), raw: trimmed };
            } catch (err) {
                return { text: trimmed, parseError: String(err) };
            }
        }
        return { text: trimmed };
    }

    function enrich(value) {
        if (typeof value === "string" && isJwt(value)) {
            try {
                const decoded = decodeJwt(value);
                return { _jwt: true, header: decoded.header, payload: decoded.payload, raw: value };
            } catch (err) {
                return value;
            }
        }
        if (Array.isArray(value)) return value.map(enrich);
        if (value && typeof value === "object") {
            const out = {};
            Object.keys(value).forEach((k) => {
                out[k] = enrich(value[k]);
            });
            return out;
        }
        return value;
    }

    function openModal(result) {
        const modal = $("modal");
        $("modalTitle").textContent = result.title;
        $("modalMeta").textContent = result.meta + (result.ok ? "" : " · failed");
        const parsed = parseBody(result.text, result.contentType);
        const pretty = $("modalPretty");
        const raw = $("modalRaw");
        pretty.innerHTML = renderPretty(parsed);
        raw.textContent = prettyRaw(parsed, result.text);
        showPane("pretty");
        modal.hidden = false;
        document.body.style.overflow = "hidden";
    }

    function closeModal() {
        $("modal").hidden = true;
        document.body.style.overflow = "";
    }

    function showPane(name) {
        document.querySelectorAll(".modal-tabs .tab").forEach((btn) => {
            btn.classList.toggle("is-active", btn.getAttribute("data-pane") === name);
        });
        $("modalPretty").hidden = name !== "pretty";
        $("modalRaw").hidden = name !== "raw";
    }

    function prettyRaw(parsed, text) {
        if (parsed.json) return JSON.stringify(parsed.json, null, 2);
        if (parsed.jwt) return JSON.stringify({ header: parsed.jwt.header, payload: parsed.jwt.payload }, null, 2);
        return text;
    }

    function renderPretty(parsed) {
        if (parsed.empty) return '<p class="muted">Empty response</p>';
        if (parsed.jwt) {
            return (
                renderJwtBlock(parsed.jwt) +
                '<div class="json-tree">' +
                renderTree(enrich(parsed.jwt.payload), 0) +
                "</div>"
            );
        }
        if (parsed.json) {
            const data = parsed.json;
            const chain = data.chain || data.trust_chain;
            let html = "";
            if (Array.isArray(chain) && chain.length) {
                html += renderChain(chain);
            }
            html += '<div class="json-tree">' + renderTree(enrich(data), 0) + "</div>";
            return html;
        }
        if (parsed.parseError) {
            return "<p class=\"muted\">" + escapeHtml(parsed.parseError) + "</p><pre class=\"raw-view\">" + escapeHtml(parsed.text) + "</pre>";
        }
        return "<pre class=\"raw-view\">" + escapeHtml(parsed.text) + "</pre>";
    }

    function renderJwtBlock(jwt) {
        const sub = jwt.payload && (jwt.payload.sub || jwt.payload.iss);
        return (
            '<div class="chain-step" style="margin-bottom:12px"><h3>Signed JWT</h3><p>' +
            escapeHtml((jwt.header && jwt.header.typ) || "JWT") +
            (sub ? " · " + escapeHtml(String(sub)) : "") +
            "</p></div>"
        );
    }

    function renderChain(chain) {
        const steps = chain
            .map((item, i) => {
                const sub = item.subject || item.sub || item.entity_id || "statement " + (i + 1);
                const iss = item.issuer || item.iss || "";
                return (
                    '<div class="chain-step"><h3>' +
                    (i + 1) +
                    ". " +
                    escapeHtml(sub) +
                    "</h3><p>iss " +
                    escapeHtml(iss) +
                    (item.validated ? " · validated" : "") +
                    "</p></div>"
                );
            })
            .join("");
        return '<div class="chain-steps">' + steps + "</div>";
    }

    function renderTree(value, depth) {
        if (value && value._jwt) {
            return (
                '<span class="json-key">JWT</span> ' +
                renderTree({ header: value.header, payload: value.payload }, depth)
            );
        }
        if (value === null) return '<span class="json-null">null</span>';
        if (typeof value === "string") return '<span class="json-str">"' + escapeHtml(value) + '"</span>';
        if (typeof value === "number") return '<span class="json-num">' + escapeHtml(String(value)) + "</span>";
        if (typeof value === "boolean") return '<span class="json-bool">' + value + "</span>";
        if (Array.isArray(value)) {
            if (!value.length) return "[]";
            const inner = value
                .map((v, i) => '<div class="tree-block">' + i + ": " + renderTree(v, depth + 1) + "</div>")
                .join("");
            return collapsible("[", inner, "]", depth < 2);
        }
        if (typeof value === "object") {
            const keys = Object.keys(value);
            if (!keys.length) return "{}";
            const inner = keys
                .map(
                    (k) =>
                        '<div class="tree-block"><span class="json-key">' +
                        escapeHtml(k) +
                        "</span>: " +
                        renderTree(value[k], depth + 1) +
                        "</div>"
                )
                .join("");
            return collapsible("{", inner, "}", depth < 2);
        }
        return escapeHtml(String(value));
    }

    function collapsible(open, inner, close, expanded) {
        const id = "n" + Math.random().toString(36).slice(2);
        return (
            '<button class="tree-toggle" type="button" data-target="' +
            id +
            '">' +
            (expanded ? "−" : "+") +
            "</button>" +
            open +
            '<div id="' +
            id +
            '" class="' +
            (expanded ? "" : "tree-collapsed") +
            '">' +
            inner +
            "</div>" +
            close
        );
    }

    function escapeHtml(value) {
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function escapeAttr(value) {
        return escapeHtml(value).replace(/'/g, "&#39;");
    }

    function toast(message) {
        const el = document.createElement("div");
        el.className = "toast";
        el.textContent = message;
        document.body.appendChild(el);
        setTimeout(() => el.remove(), 2400);
    }

    async function clearCache(kind) {
        const urls = {
            entities: "/api/v1/cache/clear-entities",
            chains: "/api/v1/cache/clear-chains",
            all: "/api/v1/cache/clear-all",
        };
        const labels = { entities: "entity cache", chains: "trust chain cache", all: "all caches" };
        if (!window.confirm("Clear " + labels[kind] + "?")) return;
        if (state.operatorRequired && !storedApiKey()) {
            showLock("Cache changes require the resolver API_KEY.");
            return;
        }
        const res = await apiFetch(urls[kind], { method: "POST" });
        if (res.status === 401) {
            toast("Clear failed");
            return;
        }
        toast(res.ok ? "Cleared " + labels[kind] : "Clear failed");
        refreshCacheLists();
        poll();
    }

    function bind() {
        document.querySelectorAll(".topbar .tab").forEach((btn) => {
            btn.addEventListener("click", () => setView(btn.getAttribute("data-view")));
        });
        $("themeBtn").addEventListener("click", () => {
            const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
            applyTheme(next);
        });
        $("signOutBtn").addEventListener("click", () => {
            setStoredApiKey("");
        });
        $("lockForm").addEventListener("submit", (ev) => {
            ev.preventDefault();
            const value = $("apiKeyInput").value.trim();
            if (!value) {
                showLock("Enter the API key.");
                return;
            }
            setStoredApiKey(value);
            $("apiKeyInput").value = "";
            hideLock();
            poll();
            if (state.view === "inspect") refreshCacheLists();
        });
        $("pauseBtn").addEventListener("click", () => {
            state.paused = !state.paused;
            $("pauseBtn").textContent = state.paused ? "Resume" : "Pause";
            $("livePill").classList.toggle("is-paused", state.paused);
            $("liveLabel").textContent = state.paused ? "Paused" : "Live";
        });
        document.querySelectorAll("[data-cache]").forEach((btn) => {
            btn.addEventListener("click", () => clearCache(btn.getAttribute("data-cache")));
        });
        $("inspectForm").addEventListener("submit", (ev) => {
            ev.preventDefault();
            runInspect("entity");
        });
        document.querySelectorAll("#inspectForm [data-action]").forEach((btn) => {
            btn.addEventListener("click", () => runInspect(btn.getAttribute("data-action")));
        });
        $("cachedEntities").addEventListener("click", (ev) => {
            const row = ev.target.closest("tr[data-id]");
            if (!row) return;
            $("entityId").value = row.getAttribute("data-id");
            if (row.getAttribute("data-ta")) $("trustAnchor").value = row.getAttribute("data-ta");
            runInspect("cached-entity", row.getAttribute("data-id"), row.getAttribute("data-ta"));
        });
        $("cachedChains").addEventListener("click", (ev) => {
            const row = ev.target.closest("tr[data-id]");
            if (!row) return;
            $("entityId").value = row.getAttribute("data-id");
            runInspect("cached-chain", row.getAttribute("data-id"), "");
        });
        $("modal").addEventListener("click", (ev) => {
            if (ev.target.getAttribute("data-close")) closeModal();
            const pane = ev.target.getAttribute("data-pane");
            if (pane) showPane(pane);
            const toggle = ev.target.closest(".tree-toggle");
            if (toggle) {
                const target = document.getElementById(toggle.getAttribute("data-target"));
                if (target) {
                    const collapsed = target.classList.toggle("tree-collapsed");
                    toggle.textContent = collapsed ? "+" : "−";
                }
            }
        });
        document.addEventListener("keydown", (ev) => {
            if (ev.key === "Escape") closeModal();
        });
        window.addEventListener("resize", () => Object.values(charts).forEach((c) => c && c.draw()));
    }

    initTheme();
    initCharts();
    bind();
    setBrandSub();
    checkAuth().then(poll);
    setInterval(poll, POLL_MS);
    setInterval(() => {
        if (state.view === "inspect") refreshCacheLists();
    }, 8000);
})();
