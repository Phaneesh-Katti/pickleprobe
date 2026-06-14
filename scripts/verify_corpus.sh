#!/usr/bin/env bash
# Verify PickleBall corpus archives are fully downloaded.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${ROOT}/tests/corpus/archives"

declare -A EXPECTED=(
  ["pickleball-source.tar.gz"]=6180467
  ["pickleball-malicious.tar.gz"]=10179996841
  ["pickleball-benign-abridged.tar.gz"]=9618678863
)

ok=true
for name in "${!EXPECTED[@]}"; do
  path="${ARCH}/${name}"
  want="${EXPECTED[$name]}"
  if [[ ! -f "${path}" ]]; then
    echo "MISSING  ${name}"
    ok=false
    continue
  fi
  got=$(stat -c%s "${path}")
  if [[ "${got}" -eq "${want}" ]]; then
    echo "OK       ${name}  (${got} bytes)"
  else
    pct=$(( got * 100 / want ))
    echo "PARTIAL  ${name}  (${got} / ${want} bytes, ${pct}%)"
    ok=false
  fi
done

if [[ "${ok}" == true ]]; then
  echo ""
  echo "All archives complete."
  exit 0
fi
echo ""
echo "Run ./scripts/download_corpus.sh to resume incomplete downloads."
exit 1
