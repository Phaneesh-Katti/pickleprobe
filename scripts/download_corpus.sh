#!/usr/bin/env bash
# OPTIONAL: full PickleBall Zenodo archives (~19 GB).
# For day-to-day dev use scripts/fetch_curated_corpus.sh instead (~12 KB).
# Archives are kept compressed; Polyglot will support reading them directly later.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVES="${ROOT}/tests/corpus/archives"
ZENODO="https://zenodo.org/api/records/16974645/files"

mkdir -p "${ARCHIVES}"

download() {
  local remote_name="$1"
  local local_name="$2"
  local dest="${ARCHIVES}/${local_name}"
  echo "==> ${local_name}"
  curl -fL --retry 5 --retry-delay 10 -C - \
    -o "${dest}" \
    "${ZENODO}/${remote_name}/content"
  echo "    saved: ${dest} ($(du -h "${dest}" | cut -f1))"
}

echo "Corpus archives directory: ${ARCHIVES}"
echo "Total download size: ~19 GB (malicious ~9.5 GB + benign-abridged ~9.0 GB)"
echo ""

if [[ "${1:-}" == "--malicious-only" ]]; then
  download "malicious.tar.gz" "pickleball-malicious.tar.gz"
elif [[ "${1:-}" == "--benign-only" ]]; then
  download "benign-abridged.tar.gz" "pickleball-benign-abridged.tar.gz"
elif [[ "${1:-}" == "--source-only" ]]; then
  download "pickleball.tar.gz" "pickleball-source.tar.gz"
else
  download "pickleball.tar.gz" "pickleball-source.tar.gz"
  download "malicious.tar.gz" "pickleball-malicious.tar.gz"
  download "benign-abridged.tar.gz" "pickleball-benign-abridged.tar.gz"
fi

echo ""
echo "Done. See tests/corpus/README.md for archive descriptions."
