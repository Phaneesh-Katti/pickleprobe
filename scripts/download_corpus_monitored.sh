#!/usr/bin/env bash
# PickleBall Zenodo download with live progress monitoring.
# Archives stay compressed under tests/corpus/archives/ (~19 GB total).
#
# Usage:
#   ./scripts/download_corpus_monitored.sh --parallel     # malicious + benign + source concurrently
#   ./scripts/download_corpus_monitored.sh --malicious-only
#   ./scripts/download_corpus_monitored.sh              # sequential (default)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVES="${ROOT}/tests/corpus/archives"
ZENODO="https://zenodo.org/api/records/16974645/files"
POLL_SECS=5
STALL_LIMIT=12

mkdir -p "${ARCHIVES}"

declare -A EXPECTED=(
  ["pickleball-source.tar.gz"]=6180467
  ["pickleball-malicious.tar.gz"]=10179996841
  ["pickleball-benign-abridged.tar.gz"]=9618678863
)

declare -A REMOTE=(
  ["pickleball-source.tar.gz"]="pickleball.tar.gz"
  ["pickleball-malicious.tar.gz"]="malicious.tar.gz"
  ["pickleball-benign-abridged.tar.gz"]="benign-abridged.tar.gz"
)

human_bytes() {
  numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || echo "${1} bytes"
}

is_complete() {
  local name="$1"
  local dest="${ARCHIVES}/${name}"
  local expected="${EXPECTED[$name]}"
  [[ -f "${dest}" ]] && [[ "$(stat -c%s "${dest}")" -eq "${expected}" ]]
}

start_download() {
  local name="$1"
  local dest="${ARCHIVES}/${name}"
  local remote="${REMOTE[$name]}"

  if is_complete "${name}"; then
    echo "[skip] ${name} already complete"
    return 0
  fi

  echo "[start] ${name} ← ${remote}"
  curl -fL \
    --retry 20 --retry-delay 30 --retry-all-errors \
    --connect-timeout 30 \
    -C - \
    -o "${dest}" \
    "${ZENODO}/${remote}/content" &
  echo $! > "${ARCHIVES}/.${name}.pid"
}

monitor_jobs() {
  local -a names=("$@")
  declare -A last_size
  declare -A stall

  echo ""
  echo "Monitoring ${#names[@]} download(s), poll every ${POLL_SECS}s"
  echo "================================================================"

  while true; do
    local any_running=false
    local ts
    ts=$(date '+%H:%M:%S')
    local total_got=0
    local total_want=0

    for name in "${names[@]}"; do
      if is_complete "${name}"; then
        continue
      fi
      local pid_file="${ARCHIVES}/.${name}.pid"
      if [[ -f "${pid_file}" ]]; then
        local pid
        pid=$(cat "${pid_file}")
        if kill -0 "${pid}" 2>/dev/null; then
          any_running=true
        fi
      fi
    done

    printf "[%s]\n" "${ts}"
    for name in "${names[@]}"; do
      local dest="${ARCHIVES}/${name}"
      local expected="${EXPECTED[$name]}"
      local size=0
      [[ -f "${dest}" ]] && size=$(stat -c%s "${dest}")

      total_got=$(( total_got + size ))
      total_want=$(( total_want + expected ))

      if is_complete "${name}"; then
        printf "  %-32s  COMPLETE  %s\n" "${name}" "$(human_bytes "${expected}")"
        continue
      fi

      local pct=0
      if (( expected > 0 )); then
        pct=$(( size * 100 / expected ))
      fi

      local prev="${last_size[$name]:-0}"
      local delta=$(( size - prev ))
      local rate=$(( delta / POLL_SECS ))
      printf "  %-32s  %5s%%  %s / %s  (~%s/s)\n" \
        "${name}" "${pct}" \
        "$(human_bytes "${size}")" "$(human_bytes "${expected}")" \
        "$(human_bytes "${rate}")"

      if (( prev > 0 && delta == 0 )); then
        stall[$name]=$(( ${stall[$name]:-0} + 1 ))
        if (( stall[$name] >= STALL_LIMIT )); then
          echo "    [warn] ${name}: no growth for ~$(( STALL_LIMIT * POLL_SECS ))s"
          stall[$name]=0
        fi
      else
        stall[$name]=0
      fi
      last_size[$name]=${size}
    done

    local agg_pct=0
    if (( total_want > 0 )); then
      agg_pct=$(( total_got * 100 / total_want ))
    fi
    printf "  TOTAL  %5s%%  %s / %s\n" "${agg_pct}" "$(human_bytes "${total_got}")" "$(human_bytes "${total_want}")"
    echo "----------------------------------------------------------------"

    if [[ "${any_running}" == false ]]; then
      break
    fi
    sleep "${POLL_SECS}"
  done

  local failed=false
  for name in "${names[@]}"; do
    rm -f "${ARCHIVES}/.${name}.pid"
    if ! is_complete "${name}"; then
      echo "[error] incomplete: ${name}"
      failed=true
    fi
  done

  if [[ "${failed}" == true ]]; then
    return 1
  fi
  echo "[ok] all monitored downloads complete"
}

download_one_blocking() {
  local name="$1"
  if is_complete "${name}"; then
    echo "[skip] ${name} already complete"
    return 0
  fi
  start_download "${name}"
  monitor_jobs "${name}"
}

main() {
  echo "PickleBall corpus archives → ${ARCHIVES}"
  echo "Dataset: 336 models (malicious + benign-abridged), Columbia PickleBall / Zenodo 16974645"
  echo "Disk: ~19 GiB compressed (425+ GiB free recommended)"
  echo ""

  case "${1:-sequential}" in
    --parallel)
      local jobs=()
      for name in pickleball-source.tar.gz pickleball-malicious.tar.gz pickleball-benign-abridged.tar.gz; do
        if ! is_complete "${name}"; then
          start_download "${name}"
          jobs+=("${name}")
        else
          echo "[skip] ${name} already complete"
        fi
      done
      if ((${#jobs[@]} == 0)); then
        echo "Nothing to download."
      else
        monitor_jobs "${jobs[@]}"
      fi
      ;;
    --malicious-only) download_one_blocking "pickleball-malicious.tar.gz" ;;
    --benign-only)    download_one_blocking "pickleball-benign-abridged.tar.gz" ;;
    --source-only)    download_one_blocking "pickleball-source.tar.gz" ;;
    sequential|*)
      download_one_blocking "pickleball-source.tar.gz"
      download_one_blocking "pickleball-malicious.tar.gz"
      download_one_blocking "pickleball-benign-abridged.tar.gz"
      ;;
  esac

  echo ""
  "${ROOT}/scripts/verify_corpus.sh"
}

main "$@"
