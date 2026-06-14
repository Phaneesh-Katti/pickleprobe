#!/usr/bin/env bash
# Download real-world pickle evaluation samples from published sources only.
# No synthetic / hand-crafted bytecode in this repo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${ROOT}/tests/corpus/samples"

HF_WOLF="https://huggingface.co/WolfpackArmy/pytorch-pickle-rce-poc/resolve/main"
HF_RODION="https://huggingface.co/Rodion111/pytorch-pt2-ace-poc/resolve/main"
PSCAN="https://raw.githubusercontent.com/mmaitre314/picklescan/main/tests/data"

mkdir -p "${DEST}/wolfpack-army" "${DEST}/picklescan" "${DEST}/rodion111"

echo "==> WolfpackArmy / HuggingFace PyTorch RCE PoC (published research)"
curl -fL -o "${DEST}/wolfpack-army/poc_torchsave.pt"       "${HF_WOLF}/poc_torchsave.pt"
curl -fL -o "${DEST}/wolfpack-army/poc_evil_statedict.pt" "${HF_WOLF}/poc_evil_statedict.pt"
curl -fL -o "${DEST}/wolfpack-army/benign_model.pt"        "${HF_WOLF}/benign_model.pt"
curl -fL -o "${DEST}/wolfpack-army/benign_torchscript.pt"  "${HF_WOLF}/benign_torchscript.pt"

echo "==> Rodion111 / PyTorch .pt2 ACE PoC (CVE-style fallback bypass)"
curl -fL -o "${DEST}/rodion111/malicious.pt2" "${HF_RODION}/malicious.pt2"

echo "==> picklescan reference corpus (mmaitre314/picklescan — HF Hub scanner test set)"
# Hand-picked from picklescan tests/data for technique diversity (~KB each)
for f in \
  malicious0.pkl \
  malicious15a.pkl \
  malicious15b.pkl \
  sys_module_override_sploit.pkl \
  pytorch_magic_bypass.pt \
  benign0_v4.pkl \
  new_pytorch_model.bin
do
  curl -fL -o "${DEST}/picklescan/${f}" "${PSCAN}/${f}"
done

echo ""
echo "Done. $(find "${DEST}" -type f | wc -l) files under tests/corpus/samples/"
find "${DEST}" -type f -exec ls -lh {} \;
