# PickleProbe vs naive GLOBAL scanner vs picklescan

Comparison on the real-world manifest in `tests/corpus/manifest.yaml` (12 samples from WolfpackArmy, Rodion111, picklescan).

## Scanners

| Scanner | What it checks |
|---------|----------------|
| **Naive GLOBAL** | `pickletools.genops` → only `GLOBAL` opcode args matching known sink pairs |
| **PickleProbe** | PVM emulation: `GLOBAL`, `STACK_GLOBAL`, `REDUCE`, `BUILD`, `NEWOBJ`, memo, gadget folding |
| **picklescan** | Production blocklist over globals/imports (install separately) |

## Regenerate tables

```bash
python scripts/benchmark_corpus.py
python scripts/compare_picklescan.py   # pip install picklescan
```

## Takeaways (PickleProbe vs naive GLOBAL)

1. **`STACK_GLOBAL` bypasses GLOBAL grep** — e.g. `picklescan/malicious15b.pkl` (`bdb.Bdb.run`), `rodion111/malicious.pt2` (`subprocess.check_output`).
2. **PyTorch ZIP** — inner `data.pkl` streams analyzed via `formats.loader`.
3. **Debugger gadgets** — `bdb`/`pdb` chain primitives align with picklescan/HF blocklist extensions.
4. **Real PoCs only** — corpus is downloaded from published HF repos and picklescan `tests/data`, not synthetic opcode vectors.

## picklescan comparison

When `picklescan` is installed, `scripts/compare_picklescan.py` runs both tools on each manifest file. Expect agreement on obvious `eval` chains; divergences on STACK_GLOBAL-heavy samples illustrate why PVM simulation matters.

## Corpus coverage

- Malicious samples: WolfpackArmy `.pt`, Rodion111 `.pt2`, picklescan regression set.
- Benign samples: WolfpackArmy controls + picklescan `benign0_v4.pkl` + small `pytorch_model.bin`.
- Full PickleBall (336 models): optional Zenodo download — not required for CI.

Fetch corpus:

```bash
./scripts/fetch_corpus.sh
```
