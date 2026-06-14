#!/usr/bin/env bash
# Foreground corpus download with 5-second progress monitoring.
# Does NOT detach — safe to run in a real terminal for multi-GB transfers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVES="${ROOT}/tests/corpus/archives"
ZENODO="https://zenodo.org/api/records/16974645/files"
POLL_SECS=5
STALL_LIMIT=12  # alert after N polls with zero byte growth (~60s)

mkdir -p "${ARCHIVES}"

declare -A EXPECTED=(
  ["pickleball-source.tar.gz"]=6180467
  ["pickleball-malicious.tar.gz"]=10179996841
  ["pickleball-benign-abridged.tar.gz"]=9618678863
)

human_bytes() {
  numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || echo "${1} bytes"
}

monitor_wait() {
  local label="$1"
  local dest="$2"
  local expected="$3"
  local pid="$4"
  local last_size=-1
  local stall=0

  echo ""
  echo "Monitoring ${label} (pid ${pid}), poll every ${POLL_SECS}s"
  echo "Expected: $(human_bytes "${expected}")"
  echo "----------------------------------------"

  while kill -0 "${pid}" 2>/dev/null; do
    sleep "${POLL_SECS}"
    local size=0
    [[ -f "${dest}" ]] && size=$(stat -c%s "${dest}")

    local pct=0
    if (( expected > 0 )); then
      pct=$(( size * 100 / expected ))
    fi

    local delta=$(( size - last_size ))
    local rate=$(( delta / POLL_SECS ))
    echo "$(date '+%H:%M:%S')  $(human_bytes "${size}") / $(human_bytes "${expected}")  (${pct}%)  +$(human_bytes "${delta}") in ${POLL_SECS}s  (~$(human_bytes "${rate}")/s)"

    if (( last_size >= 0 && delta == 0 )); then
      stall=$(( stall + 1 ))
      echo "  [warn] no growth (${stall}/${STALL_LIMIT})"
      if (( stall >= STALL_LIMIT )); then
        echo "  [error] stalled — curl still running; check network"
        stall=0
      fi
    else
      stall=0
    fi
    last_size=${size}
  done

  if ! wait "${pid}"; then
    echo "[error] curl failed for ${label}"
    return 1
  fi

  local final=$(stat -c%s "${dest}")
  if (( final != expected )); then
    echo "[error] size mismatch: got ${final}, want ${expected}"
    return 1
  fi
  echo "[ok] ${label} complete"
}

download_one() {
  local remote_name="$1"
  local local_name="$2"
  local dest="${ARCHIVES}/${local_name}"
  local expected="${EXPECTED[$local_name]}"

  if [[ -f "${dest}" ]] && [[ "$(stat -c%s "${dest}")" -eq "${expected}" ]]; then
    echo "[skip] ${local_name} already complete"
    return 0
  fi

  echo "==> Downloading ${local_name}"
  echo "    URL: ${ZENODO}/${remote_name}/content"

  # Foreground curl in subshell background job — parent monitors; no nohup.
  curl -fL \
    --retry 20 --retry-delay 30 --retry-all-errors \
    --connect-timeout 30 \
    -C - \
    -o "${dest}" \
    "${ZENODO}/${remote_name}/content" &
  local pid=$!

  monitor_wait "${local_name}" "${dest}" "${expected}" "${pid}"
}

main() {
  echo "Corpus archives: ${ARCHIVES}"
  echo "Poll interval: ${POLL_SECS}s"
  echo ""

  case "${1:-all}" in
    --malicious-only) download_one "malicious.tar.gz" "pickleball-malicious.tar.gz" ;;
    --benign-only)    download_one "benign-abridged.tar.gz" "pickleball-benign-abridged.tar.gz" ;;
    --source-only)    download_one "pickleball.tar.gz" "pickleball-source.tar.gz" ;;
    all|*)
      download_one "pickleball.tar.gz" "pickleball-source.tar.gz"
      download_one "malicious.tar.gz" "pickleball-malicious.tar.gz"
      download_one "benign-abridged.tar.gz" "pickleball-benign-abridged.tar.gz"
      ;;
  esac

  echo ""
  echo "All requested downloads finished."
  "${ROOT}/scripts/verify_corpus.sh"
}

main "$@"
