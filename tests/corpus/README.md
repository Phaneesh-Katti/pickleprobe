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

## Optional full PickleBall (~19 GiB compressed, gitignored)

Columbia [PickleBall](https://github.com/columbia/pickleball) Zenodo record — **336 models** in three archives. Stays on disk as `.tar.gz`; PickleProbe reads members directly (no full extract).

```bash
# Parallel download + live progress (malicious + benign + source concurrently)
./scripts/download_corpus_monitored.sh --parallel

# Or sequential resume-friendly download
./scripts/download_corpus.sh

./scripts/verify_corpus.sh   # byte-size checksums

# Analyze archive in place (per-member scan with streaming progress)
pickleprobe scan tests/corpus/archives/pickleball-malicious.tar.gz --progress --limit 10
pickleprobe analyze tests/corpus/archives/pickleball-malicious.tar.gz --member ours/call_system.pkl

# Hand-picked subset benchmark (~8 members, fast repeatable eval)
python scripts/benchmark_pickleball_subset.py
```
