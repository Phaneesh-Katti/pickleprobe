# Evaluation corpus

**Real published datasets only** — no hand-crafted or `pickle.dumps()` evaluation samples in this repo.

Total tracked size: **~12 KB** (12 files). Refresh anytime:

```bash
./scripts/fetch_corpus.sh
```

## Sources

| Source | Files | Why included |
|--------|-------|--------------|
| [WolfpackArmy HF PoC](https://huggingface.co/WolfpackArmy/pytorch-pickle-rce-poc) | 4× `.pt` | Canonical PyTorch pickle RCE research repo |
| [Rodion111 .pt2 ACE](https://huggingface.co/Rodion111/pytorch-pt2-ace-poc) | 1× `.pt2` | Real `weights_only` fallback bypass PoC |
| [picklescan tests/data](https://github.com/mmaitre314/picklescan/tree/main/tests/data) | 7× mixed | HF Hub scanner reference corpus |

## What we deliberately exclude

- Hand-written `cos\nsystem\n` opcode vectors
- Locally generated `pickle.dumps()` fixtures
- Fickling `inject_*.py` outputs (synthetic until run)
- Full [PickleBall Zenodo](https://zenodo.org/records/16974645) archives (~19 GB) — optional via `./scripts/download_corpus.sh`

## Safety

Never `pickle.load()` or `torch.load(weights_only=False)` on malicious samples outside an isolated VM. PickleProbe analyzes them statically only.

## Manifest

Ground truth and expected findings: `manifest.yaml` (version 3, 12 samples).

## Optional full PickleBall

```bash
./scripts/download_corpus.sh --source-only   # 6 MB tool source
./scripts/download_corpus.sh                 # full ~19 GB archives (local only, gitignored)
```
