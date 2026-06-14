# Polyglot vs naive GLOBAL scanner

Comparison on the curated corpus in `tests/corpus/manifest.yaml`.

## Scanners

| Scanner | What it checks |
|---------|----------------|
| **Naive GLOBAL** | `pickletools.genops` → only `GLOBAL` opcode args matching known `(module, name)` sink pairs |
| **Polyglot** | Full PVM emulation: `GLOBAL`, `STACK_GLOBAL`, `REDUCE`, `BUILD`, `NEWOBJ`, memo indirection, gadget folding (`getattr` → `os.system`) |

## Results (11 manifest samples)

| Sample | Label | Naive sinks | Polyglot sinks | Gap |
|--------|-------|-------------|----------------|-----|
| benign-datetime-p0 | benign | 0 | 0 | clean |
| benign-dict-p4 | benign | 0 | 0 | clean |
| benign-tuple-p2 | benign | 0 | 0 | clean |
| benign-newobj-build-p2 | benign | 0 | 0 | clean |
| benign-pytorch-model | benign | 0 | 0 | clean |
| benign-pytorch-torchscript | benign | 0 | 0 | clean |
| mal-global-os-system | malicious | 1 | 1 | both |
| mal-stack-global-literal | malicious | 0 | 1 | **polyglot-only** |
| mal-stack-global-memo | malicious | 0 | 1 | **polyglot-only** |
| mal-pytorch-torchsave | malicious | 1 | 1 | both |
| mal-pytorch-statedict | malicious | 1 | 1 | both |

Regenerate this table:

```bash
./polyglot/bin/python scripts/benchmark_corpus.py
```

## Takeaways

1. **STACK_GLOBAL bypasses naive GLOBAL grep** — module/name come from stack strings, not a `GLOBAL` opcode arg. Polyglot resolves them via PVM simulation.
2. **Memo indirection** — same attack with `PUT`/`GET` restoring strings before `STACK_GLOBAL`; still invisible to GLOBAL-only scanning.
3. **PyTorch `.pt` files** — Polyglot unwraps ZIP archives and analyzes inner `*.pkl` streams (`formats.loader`).
4. **BUILD / NEWOBJ** — Polyglot records `__setstate__` / `__dict__` updates and `cls.__new__` sites with `INSTANCE_FLOW` / `STATE_FLOW` CFG edges (no extra detections on this small corpus yet, but required for state-based gadgets).
5. **Gadget chains** — `getattr(__import__('os'), 'system')` has no `GLOBAL os system`; covered by REDUCE folding tests (`test_reduce_analysis.py`).

## Corpus coverage

- **5/5 malicious** samples on disk detected by Polyglot.
- **2/5 malicious** missed by naive GLOBAL scanner (both STACK_GLOBAL techniques).
- Benign samples: no false SINK flags.

Fetch missing HuggingFace `.pt` samples:

```bash
./scripts/fetch_curated_corpus.sh
```
