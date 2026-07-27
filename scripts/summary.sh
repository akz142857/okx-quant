#!/usr/bin/env bash
set -u

SERVICE_NAME="${OKX_QUANT_SERVICE:-okx-quant}"
STATE_DIR="${OKX_QUANT_STATE_DIR:-/var/lib/okx-quant/production}"
LOG_FILE="${OKX_QUANT_LOG_FILE:-/var/log/okx-quant/quant.log}"

echo "== OKX Quant summary =="
echo "time: $(date --iso-8601=seconds)"
echo "service: ${SERVICE_NAME}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl show "${SERVICE_NAME}" \
    --property=ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec \
    --no-pager 2>/dev/null || echo "service unit not found"
else
  echo "systemctl unavailable"
fi

echo
echo "== Recent risk/order events =="
if command -v journalctl >/dev/null 2>&1; then
  journalctl -u "${SERVICE_NAME}" --since "24 hours ago" --no-pager 2>/dev/null \
    | grep -E "下单|止损|止盈|风控|ERROR|WARNING" \
    | tail -n 30 || true
else
  echo "journalctl unavailable"
fi

echo
echo "== Runtime state =="
if [[ -d "${STATE_DIR}" ]]; then
  find "${STATE_DIR}" -maxdepth 1 -type f \
    \( -name 'heartbeat' -o -name '*.db' -o -name '*.lock' \) \
    -print 2>/dev/null || true
else
  echo "state directory not found: ${STATE_DIR}"
fi

echo
echo "== Recent application log =="
if [[ -f "${LOG_FILE}" ]]; then
  tail -n 20 "${LOG_FILE}"
else
  echo "log file not found: ${LOG_FILE}"
fi
