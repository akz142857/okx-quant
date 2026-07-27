#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-preflight}"
if [[ "${MODE}" != "preflight" && "${MODE}" != "post-start" ]]; then
  echo "usage: $0 [preflight|post-start]" >&2
  exit 64
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${OKX_QUANT_ENV_FILE:-/etc/okx-quant/production.env}"
BACKUP_ENV_FILE="${OKX_QUANT_BACKUP_ENV_FILE:-/etc/okx-quant/backup.env}"
WATCHDOG_ENV_FILE="${OKX_QUANT_WATCHDOG_ENV_FILE:-/etc/okx-quant/watchdog.env}"
CONFIG_FILE="${OKX_QUANT_CONFIG_FILE:-/etc/okx-quant/config.yaml}"
SERVICE_NAME="${OKX_QUANT_SERVICE:-okx-quant}"
PYTHON_BIN="${OKX_QUANT_PYTHON_BIN:-/opt/okx-quant/venv/bin/python}"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="${PROJECT_DIR}/.venv/bin/python"
fi

echo "== Verify OKX Quant deployment =="
echo "project: ${PROJECT_DIR}"

test -f "${CONFIG_FILE}"
test -x "${PYTHON_BIN}"

check_secret_file() {
  local path="$1"
  local expected_owner="$2"
  local mode owner
  test -f "${path}"
  test ! -L "${path}"
  mode="$(stat -c '%a' "${path}")"
  owner="$(stat -c '%U:%G' "${path}")"
  if [[ "${mode}" != "600" && "${mode}" != "640" ]]; then
    echo "unsafe secret mode: ${path} is ${mode}, expected 600/640" >&2
    exit 1
  fi
  if [[ "${owner}" != "${expected_owner}" ]]; then
    echo "unsafe secret owner: ${path} is ${owner}, expected ${expected_owner}" >&2
    exit 1
  fi
}

check_public_key() {
  local path="$1"
  local mode owner
  test -s "${path}"
  test ! -L "${path}"
  mode="$(stat -c '%a' "${path}")"
  owner="$(stat -c '%U' "${path}")"
  if [[ "${owner}" != "root" || $((8#${mode} & 8#022)) -ne 0 ]]; then
    echo "unsafe public key owner/mode: ${path} ${owner}:${mode}" >&2
    exit 1
  fi
}

check_root_directory_chain() {
  local path="$1"
  local mode owner
  test -d "${path}"
  test ! -L "${path}"
  mode="$(stat -c '%a' "${path}")"
  owner="$(stat -c '%U' "${path}")"
  if [[ "${owner}" != "root" || $((8#${mode} & 8#022)) -ne 0 ]]; then
    echo "unsafe production directory owner/mode: ${path} ${owner}:${mode}" >&2
    exit 1
  fi
}

check_shared_journal() {
  local directory=/var/lib/okx-quant/production
  local database="${directory}/trading.db"
  local directory_mode directory_owner database_mode database_owner
  test -d "${directory}"
  test ! -L "${directory}"
  test -f "${database}"
  test ! -L "${database}"
  directory_mode="$(stat -c '%a' "${directory}")"
  directory_owner="$(stat -c '%U:%G' "${directory}")"
  database_mode="$(stat -c '%a' "${database}")"
  database_owner="$(stat -c '%U:%G' "${database}")"
  if [[ "${directory_mode}" != "2750" ||
    "${directory_owner}" != "okxquant-trader:okxquant-data" ]]; then
    echo \
      "unsafe shared state directory: ${directory_owner}:${directory_mode}, expected okxquant-trader:okxquant-data:2750" \
      >&2
    exit 1
  fi
  if [[ "${database_mode}" != "640" ||
    "${database_owner}" != "okxquant-trader:okxquant-data" ]]; then
    echo \
      "unsafe shared journal: ${database_owner}:${database_mode}, expected okxquant-trader:okxquant-data:640" \
      >&2
    exit 1
  fi
}

check_secret_file "${ENV_FILE}" "root:okxquant-trader"
check_secret_file "${BACKUP_ENV_FILE}" "root:okxquant-backup"
check_secret_file "${WATCHDOG_ENV_FILE}" "root:okxquant-watchdog"
check_secret_file \
  /etc/okx-quant/keys/backup-manifest-private.pem \
  "root:okxquant-backup"
check_public_key /etc/okx-quant/keys/control-approval-public.pem
check_public_key /etc/okx-quant/keys/risk-approval-public.pem
check_public_key /etc/okx-quant/keys/demo-monitor-public.pem
check_public_key /etc/okx-quant/keys/research-policy-public.pem
check_public_key /etc/okx-quant/keys/backup-manifest-public.pem
check_public_key /etc/okx-quant/launch.json
check_public_key "${CONFIG_FILE}"
check_public_key /etc/okx-quant/admission/evidence.json
check_public_key /etc/okx-quant/admission/approval.json
check_root_directory_chain /etc/okx-quant
check_root_directory_chain /etc/okx-quant/keys
check_root_directory_chain /etc/okx-quant/admission
check_shared_journal

if [[ "${MODE}" == "preflight" ]]; then
echo "[1/7] compile"
"${PYTHON_BIN}" -m compileall -q \
  "${PROJECT_DIR}/main.py" "${PROJECT_DIR}/okx_quant" "${PROJECT_DIR}/scripts"

echo "[2/7] static correctness and high-severity security scan"
cd "${PROJECT_DIR}"
"${PYTHON_BIN}" -m ruff check main.py okx_quant scripts tests
"${PYTHON_BIN}" -m bandit -q -r okx_quant scripts -lll -iii

echo "[3/7] tests and state-machine branch coverage"
"${PYTHON_BIN}" -m pytest -q \
  --cov=okx_quant \
  --cov-config=.coveragerc-core \
  --cov-branch \
  --cov-report=term-missing \
  --cov-fail-under=95

echo "[4/7] fault injection"
"${PYTHON_BIN}" scripts/fault_injection.py \
  --verify-evidence "${PROJECT_DIR}/fault-injection.json" \
  --revision-file "${PROJECT_DIR}/REVISION"

echo "[5/7] strong config validation"
"${PYTHON_BIN}" -c \
  'import sys; from main import load_env_file; from okx_quant.config import load_yaml, ProductionSettings; load_env_file(sys.argv[1]); ProductionSettings.from_config(load_yaml(sys.argv[2]))' \
  "${ENV_FILE}" "${CONFIG_FILE}"

echo "[6/7] OKX connectivity and authentication (read-only)"
"${PYTHON_BIN}" scripts/test_api.py \
  --env-file "${ENV_FILE}" \
  --config "${CONFIG_FILE}"

echo "[7/7] isolated service identities and admission precheck"
if command -v systemctl >/dev/null 2>&1; then
  systemctl cat "${SERVICE_NAME}" >/dev/null
  test "$(systemctl show -p User --value okx-quant.service)" = "okxquant-trader"
  test "$(systemctl show -p User --value okx-quant-watchdog.service)" = "okxquant-watchdog"
  test "$(systemctl show -p User --value okx-quant-daily-backup.service)" = "okxquant-backup"
  systemctl show -p ExecStart --value okx-quant.service |
    grep -F "production_launch.py" >/dev/null
  systemctl show -p ExecStartPre --value okx-quant.service |
    grep -F "activate_release.py" >/dev/null
else
  echo "systemctl unavailable" >&2
  exit 1
fi
echo "deployment preflight passed; service has not been started or validated"
exit 0
fi

post_start_fail_safe() {
  local exit_code=$?
  local status_json=""
  local status_mode=""
  trap - ERR
  set +e
  status_json="$("${PYTHON_BIN}" "${PROJECT_DIR}/main.py" \
    --env-file "${ENV_FILE}" \
    --config "${CONFIG_FILE}" production-status 2>/dev/null)"
  status_mode="$(printf '%s' "${status_json}" |
    "${PYTHON_BIN}" -c \
      'import json,sys; print(json.load(sys.stdin).get("mode", ""))' \
      2>/dev/null)"
  if systemctl is-active "${SERVICE_NAME}" >/dev/null 2>&1 &&
    curl --fail --silent --max-time 3 \
      http://127.0.0.1:9108/healthz >/dev/null &&
    [[ "${status_mode}" =~ ^(halted|emergency_exit|maintenance)$ ]]; then
    echo \
      "post-start rejected: verified hard-safe protection kernel remains live; service preserved" \
      >&2
    if ! "${PYTHON_BIN}" "${PROJECT_DIR}/scripts/page_service_failure.py" \
      --env-file "${ENV_FILE}" \
      --service "${SERVICE_NAME}:post-start-rejected" \
      --webhook-env OKX_QUANT_ALERT_WEBHOOK; then
      echo \
        "Page delivery failed: deployment rejected while hard-safe protection kernel remains live" \
        >&2
      if command -v systemd-cat >/dev/null 2>&1; then
        echo \
          "Page delivery failed: deployment rejected while hard-safe protection kernel remains live" |
          systemd-cat -p crit -t okx-quant-deploy
      fi
    fi
    exit "${exit_code}"
  fi
  echo "post-start verification failed; stopping unverifiable trader fail closed" >&2
  systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1
  exit "${exit_code}"
}
trap post_start_fail_safe ERR

echo "[1/5] verify isolated dependencies before any trader restart"
test "$(systemctl show -p User --value okx-quant.service)" = "okxquant-trader"
test "$(systemctl show -p User --value okx-quant-watchdog.service)" = "okxquant-watchdog"
test "$(systemctl show -p User --value okx-quant-daily-backup.service)" = "okxquant-backup"
systemctl is-enabled okx-quant-watchdog.service >/dev/null
systemctl is-active okx-quant-watchdog.service >/dev/null
systemctl is-enabled okx-quant-daily-backup.timer >/dev/null
systemctl is-active okx-quant-daily-backup.timer >/dev/null
trader_mount="$(findmnt -n -o TARGET --target /var/lib/okx-quant/production)"
backup_mount="$(findmnt -n -o TARGET --target /var/lib/okx-quant-backup)"
test "${trader_mount}" != "${backup_mount}"
test "$(df --output=avail -B1 /var/lib/okx-quant-backup | tail -1)" -ge 5368709120
systemctl start okx-quant-daily-backup.service
test "$(systemctl show -p Result --value okx-quant-daily-backup.service)" = "success"
"${PYTHON_BIN}" "${PROJECT_DIR}/scripts/offsite_restore_check.py" \
  --backup-env "${BACKUP_ENV_FILE}" \
  --local-backup-dir /var/lib/okx-quant-backup/daily \
  --manifest-public-key /etc/okx-quant/keys/backup-manifest-public.pem \
  --output /var/lib/okx-quant-backup/last-offsite-roundtrip.json

echo "[2/5] restart the admitted release"
systemctl restart "${SERVICE_NAME}"
systemctl is-active "${SERVICE_NAME}" >/dev/null
check_public_key /var/lib/okx-quant/admission/deployment-receipt.json

echo "[3/5] verify running release identity equals immutable admission evidence"
expected_identity="$("${PYTHON_BIN}" -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["evidence_metadata"]["config_hash"])' \
  /etc/okx-quant/admission/evidence.json)"
actual_identity="$("${PYTHON_BIN}" \
  "${PROJECT_DIR}/scripts/production_launch.py" \
  --config "${CONFIG_FILE}" \
  --release-commit-file "${PROJECT_DIR}/REVISION" \
  --launch-manifest /etc/okx-quant/launch.json \
  --identity-only |
  "${PYTHON_BIN}" -c 'import json,sys; print(json.load(sys.stdin)["config_hash"])')"
test "${actual_identity}" = "${expected_identity}"

echo "[4/5] runtime readiness and local metrics"
curl --fail --silent http://127.0.0.1:9108/healthz >/dev/null
curl --fail --silent http://127.0.0.1:9108/readyz >/dev/null
curl --fail --silent http://127.0.0.1:9108/metrics >/dev/null

echo "[5/5] durable status and local online backup"
"${PYTHON_BIN}" "${PROJECT_DIR}/main.py" --env-file "${ENV_FILE}" \
  --config "${CONFIG_FILE}" production-status >/dev/null
"${PYTHON_BIN}" "${PROJECT_DIR}/main.py" --env-file "${ENV_FILE}" \
  --config "${CONFIG_FILE}" backup-now >/dev/null

trap - ERR
echo "post-start deployment verification passed"
