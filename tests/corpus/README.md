# Curated evaluation corpus

Hand-picked, **~80 KB total** — no multi-GB PickleBall download. Every sample is chosen to teach or test one specific analyzer capability.

## Why these samples (not the full archive)

| Goal | Samples |
|------|---------|
| Opcode coverage (protocol 4+) | `list_protocol4`, `set_protocol4`, `dict_protocol4` |
| BUILD / NEWOBJ | `newobj_build_protocol2` |
| Direct GLOBAL sink | `global_os_system`, `global_eval` |
| STACK_GLOBAL evasion | `stack_global_os_system` |
| Memo indirection | `stack_global_memo_indirect` |
| Gadget chains (no `GLOBAL os.system`) | `getattr_import_gadget`, `partial_os_system` |
| Suspicious-only primitive | `methodcaller_suspicious` |
| Real PyTorch ZIP payloads | WolfpackArmy HF PoCs (~1–4 KB each) |
| Benign ML-adjacent | `benign_model.pt`, `benign_torchscript.pt` |

**Total: 17 samples** — enough for CI and portfolio demos, not a research dataset.

## Refresh

```bash
./scripts/fetch_curated_corpus.sh
```

Downloads HF `.pt` files (~10 KB) and regenerates raw `.pkl` vectors.

## Safety

Never `pickle.load()` or `torch.load(weights_only=False)` on `malicious/` files outside an isolated VM. Polyglot analyzes them statically only.

## Sample index

See `manifest.yaml` for labels, techniques, and expected findings per file.

| ID | Size class | Technique |
|----|------------|-----------|
| benign-datetime-p0 | tiny | stdlib GLOBAL |
| benign-dict/list/set-p4 | tiny | protocol-4 containers |
| benign-newobj-build-p2 | tiny | NEWOBJ + BUILD |
| benign-pytorch-* | small | real HF controls |
| mal-global-* | tiny | direct sinks |
| mal-stack-global-* | tiny | lookup obfuscation |
| mal-getattr/partial | tiny | gadget chains |
| mal-methodcaller | tiny | suspicious tier |
| mal-pytorch-* | small | real HF PoCs |

## Optional full PickleBall

```bash
./scripts/download_corpus_monitored.sh   # ~19 GB — not required
```
