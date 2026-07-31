"use strict";

const state = {
  overview: null,
  positions: [],
  orders: [],
  events: [],
  loading: false,
};

const byId = (id) => document.getElementById(id);
const openStates = new Set([
  "created",
  "persisted",
  "submitting",
  "acknowledged",
  "live",
  "partially_filled",
  "unknown",
  "manual_review",
]);
const unsafeStates = new Set(["unknown", "manual_review"]);

function text(id, value) {
  const element = byId(id);
  if (element) element.textContent = value;
}

function formatNumber(value, digits = 2) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return new Intl.NumberFormat("zh-CN", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(number);
}

function formatCompact(value, digits = 6) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return new Intl.NumberFormat("zh-CN", {
    maximumFractionDigits: digits,
  }).format(number);
}

function formatMoney(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return `${number >= 0 ? "" : "−"}${formatNumber(Math.abs(number), 2)}`;
}

function formatTime(timestamp, includeDate = false) {
  const date = new Date(Number(timestamp) * 1000);
  if (!Number.isFinite(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    month: includeDate ? "2-digit" : undefined,
    day: includeDate ? "2-digit" : undefined,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function formatAge(seconds) {
  if (seconds === null || seconds === undefined || !Number.isFinite(Number(seconds))) {
    return "无数据";
  }
  const value = Math.max(0, Number(seconds));
  if (value < 1) return "< 1 秒";
  if (value < 60) return `${Math.floor(value)} 秒`;
  if (value < 3600) return `${Math.floor(value / 60)} 分 ${Math.floor(value % 60)} 秒`;
  return `${Math.floor(value / 3600)} 小时`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function statusClass(value) {
  const normalized = String(value || "neutral").toLowerCase();
  return normalized.replaceAll(/[^a-z0-9_]/g, "_");
}

async function getJson(path) {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.message || `HTTP ${response.status}`);
  }
  return response.json();
}

async function refresh() {
  if (state.loading) return;
  state.loading = true;
  byId("refreshButton").classList.add("loading");
  try {
    const [overview, positions, orders, events] = await Promise.all([
      getJson("/api/v1/overview"),
      getJson("/api/v1/positions"),
      getJson("/api/v1/orders?limit=100"),
      getJson("/api/v1/events?limit=60"),
    ]);
    state.overview = overview;
    state.positions = positions.items || [];
    state.orders = orders.items || [];
    state.events = events.items || [];
    renderAll();
    byId("errorBanner").hidden = true;
  } catch (error) {
    text("errorMessage", error.message || "正在等待下一次自动刷新。");
    byId("errorBanner").hidden = false;
    byId("livePulse").className = "live-pulse stale";
  } finally {
    state.loading = false;
    byId("refreshButton").classList.remove("loading");
  }
}

function renderOverview() {
  const data = state.overview;
  if (!data) return;

  text("schemaVersion", `v${data.schema_version}`);
  text("databaseName", data.database);
  text("systemMode", data.mode || "unknown");
  text("modeReason", data.mode_reason || "当前没有持久化模式说明。");
  text("modeEpoch", `#${data.mode_epoch}`);
  text("accountFingerprint", data.account_fingerprint || "NOT SET");
  text("lastUpdated", formatTime(data.generated_at));
  text("sourceAge", `${formatAge(data.source_age_seconds)}前`);

  const dataClassBadge = byId("dataClassBadge");
  dataClassBadge.hidden = data.data_class !== "synthetic_preview";

  const healthBadge = byId("healthBadge");
  healthBadge.className = `badge ${statusClass(data.health)}`;
  healthBadge.textContent = String(data.health).toUpperCase();
  byId("modeIndicator").className = `mode-indicator ${statusClass(data.health)}`;

  const pulse = byId("livePulse");
  pulse.className =
    Number(data.source_age_seconds) <= 30 ? "live-pulse live" : "live-pulse stale";

  text("equityValue", formatNumber(data.account.equity, 2));
  text("availableValue", formatNumber(data.account.available, 2));
  text("openPositions", data.risk.open_positions);
  text("unprotectedPositions", data.risk.unprotected_positions);
  text("openOrders", data.risk.open_orders);
  text("unsafeOrders", data.risk.unsafe_orders);
  text("realizedPnl", formatMoney(data.account.realized_pnl));
  byId("realizedPnl").className =
    Number(data.account.realized_pnl) >= 0 ? "positive" : "negative";
  const alerts = Number(data.risk.p0_alerts) + Number(data.risk.p1_alerts);
  text("activeAlerts", alerts);
  text("p0Alerts", data.risk.p0_alerts);
  text("p1Alerts", data.risk.p1_alerts);

  drawEquityChart(data.equity_series || []);
}

function drawEquityChart(points) {
  const canvas = byId("equityChart");
  const empty = byId("chartEmpty");
  const range = byId("equityRange");
  if (!points.length) {
    canvas.hidden = true;
    empty.hidden = false;
    range.textContent = "NO SNAPSHOTS";
    return;
  }

  canvas.hidden = false;
  empty.hidden = true;
  const first = points[0];
  const last = points[points.length - 1];
  range.textContent =
    points.length > 1
      ? `${formatTime(first.timestamp, true)} — ${formatTime(last.timestamp, true)}`
      : `SNAPSHOT ${formatTime(last.timestamp, true)}`;

  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(320, rect.width);
  const height = Math.max(120, rect.height);
  canvas.width = Math.floor(width * ratio);
  canvas.height = Math.floor(height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, width, height);

  const padding = { top: 12, right: 8, bottom: 12, left: 8 };
  const allValues = points.flatMap((point) => [
    Number(point.equity),
    Number(point.available),
  ]);
  let min = Math.min(...allValues);
  let max = Math.max(...allValues);
  if (min === max) {
    min -= Math.max(1, Math.abs(min) * 0.002);
    max += Math.max(1, Math.abs(max) * 0.002);
  }
  const x = (index) =>
    padding.left +
    (index / Math.max(1, points.length - 1)) *
      (width - padding.left - padding.right);
  const y = (value) =>
    padding.top +
    ((max - Number(value)) / (max - min)) *
      (height - padding.top - padding.bottom);

  ctx.strokeStyle = "#202829";
  ctx.lineWidth = 1;
  for (let index = 1; index < 4; index += 1) {
    const gridY = padding.top + (index / 4) * (height - padding.top - padding.bottom);
    ctx.beginPath();
    ctx.moveTo(padding.left, gridY);
    ctx.lineTo(width - padding.right, gridY);
    ctx.stroke();
  }

  const drawLine = (key, color, lineWidth) => {
    ctx.strokeStyle = color;
    ctx.lineWidth = lineWidth;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.beginPath();
    points.forEach((point, index) => {
      const px = x(index);
      const py = y(point[key]);
      if (index === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    });
    ctx.stroke();
  };

  drawLine("available", "#70a7ff", 1);
  drawLine("equity", "#7cf8b7", 2);
}

function renderPositions() {
  const body = byId("positionsBody");
  text("positionSummary", `${state.positions.length} ACTIVE`);
  if (!state.positions.length) {
    body.innerHTML =
      '<tr><td class="empty-row" colspan="7">当前没有持仓</td></tr>';
    return;
  }

  body.innerHTML = state.positions
    .map((position) => {
      const protection = position.protection || {};
      const protectionState =
        protection.state || position.protection_status || "unknown";
      const pnlClass = Number(position.realized_pnl) >= 0 ? "positive" : "negative";
      return `
        <tr>
          <td><span class="instrument">${escapeHtml(position.instrument)}</span></td>
          <td class="cell-stack">
            <span>${formatCompact(position.quantity)}</span>
            <small>可用 ${formatCompact(position.available_quantity)}</small>
          </td>
          <td>${formatCompact(position.average_entry_price, 8)}</td>
          <td class="${pnlClass}">${formatMoney(position.realized_pnl)}</td>
          <td class="cell-stack">
            <span>${protection.stop_loss ? formatCompact(protection.stop_loss, 8) : "—"}</span>
            <small>TP ${protection.take_profit ? formatCompact(protection.take_profit, 8) : "—"}</small>
          </td>
          <td>
            <span class="state-pill ${statusClass(protectionState)}">
              ${escapeHtml(protectionState || "unknown")}
            </span>
          </td>
          <td>${formatTime(position.updated_at, true)}</td>
        </tr>`;
    })
    .join("");
}

function filteredOrders() {
  const filter = byId("orderFilter").value;
  if (filter === "all") return state.orders;
  if (filter === "open") {
    return state.orders.filter((order) => openStates.has(order.state));
  }
  if (filter === "unsafe") {
    return state.orders.filter((order) => unsafeStates.has(order.state));
  }
  return state.orders.filter((order) => order.state === filter);
}

function renderOrders() {
  const orders = filteredOrders();
  const body = byId("ordersBody");
  text("orderSummary", `${orders.length} RECORDS`);
  if (!orders.length) {
    body.innerHTML =
      '<tr><td class="empty-row" colspan="8">没有符合条件的订单</td></tr>';
    return;
  }

  body.innerHTML = orders
    .map((order) => {
      const average = Number(order.average_fill_price);
      const id = order.exchange_order_id || order.client_order_id || order.intent_id;
      const error = order.error_message
        ? `<small title="${escapeHtml(order.error_message)}">${escapeHtml(order.error_code || "ERROR")}</small>`
        : `<small>${escapeHtml(order.exchange_state || "—")}</small>`;
      return `
        <tr>
          <td>${formatTime(order.updated_at, true)}</td>
          <td><span class="instrument">${escapeHtml(order.instrument)}</span></td>
          <td><span class="side ${statusClass(order.side)}">${escapeHtml(order.side).toUpperCase()}</span></td>
          <td class="cell-stack">
            <span>${formatCompact(order.quantity)}</span>
            <small>成交 ${formatCompact(order.filled_quantity)}</small>
          </td>
          <td class="cell-stack">
            <span class="state-pill ${statusClass(order.state)}">${escapeHtml(order.state)}</span>
            ${error}
          </td>
          <td>${average > 0 ? formatCompact(average, 8) : "—"}</td>
          <td>${escapeHtml(order.source || "—")}</td>
          <td><span class="order-id" title="${escapeHtml(id)}">${escapeHtml(id)}</span></td>
        </tr>`;
    })
    .join("");
}

function payloadSummary(payload) {
  if (!payload || typeof payload !== "object") return "";
  const entries = Object.entries(payload).slice(0, 6);
  return entries
    .map(([key, value]) => {
      const rendered =
        value && typeof value === "object" ? JSON.stringify(value) : String(value);
      return `${key}=${rendered.slice(0, 90)}`;
    })
    .join(" · ");
}

function renderEvents() {
  const list = byId("eventsList");
  text("eventSummary", `${state.events.length} EVENTS`);
  if (!state.events.length) {
    list.innerHTML = '<div class="empty-state">当前没有系统事件</div>';
    return;
  }
  list.innerHTML = state.events
    .map(
      (event) => `
        <article class="event-item">
          <time class="event-time">${formatTime(event.created_at, true)}</time>
          <span class="event-dot ${statusClass(event.severity)}"></span>
          <div class="event-name">${escapeHtml(event.name)}</div>
          <div class="event-payload">${escapeHtml(payloadSummary(event.payload) || "无附加字段")}</div>
        </article>`,
    )
    .join("");
}

function renderAll() {
  renderOverview();
  renderPositions();
  renderOrders();
  renderEvents();
}

function syncNavigation() {
  const sections = [...document.querySelectorAll(".section-anchor")];
  const links = [...document.querySelectorAll(".nav a")];
  const active =
    [...sections].reverse().find((section) => section.getBoundingClientRect().top <= 120) ||
    sections[0];
  links.forEach((link) => {
    link.classList.toggle("active", link.getAttribute("href") === `#${active.id}`);
  });
}

byId("refreshButton").addEventListener("click", refresh);
byId("orderFilter").addEventListener("change", renderOrders);
window.addEventListener("resize", () => {
  if (state.overview) drawEquityChart(state.overview.equity_series || []);
});
window.addEventListener("scroll", syncNavigation, { passive: true });

refresh();
setInterval(refresh, 5000);
