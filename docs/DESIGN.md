# PickleProbe — design overview

Five-minute read for reviewers: what this tool is, how it works, and what it deliberately does not do.

## Problem

Pickle-based ML artifacts (`.pkl`, `.pt`, `.bin`, `.pt2`) can execute arbitrary code on `pickle.load()` / `torch.load()`. Attackers hide payloads behind:

- `STACK_GLOBAL` instead of `GLOBAL os.system`
- Memo indirection (`PUT` / `GET` before lookup)
- Gadget chains (`getattr`, `partial`, debugger hooks)
- PyTorch ZIP wrappers and format-specific bypasses

Regex or GLOBAL-only import scans miss most evasion shapes.

## Architecture

```
bytes on disk
    │
    ▼
formats.loader     ──► raw pickle | PyTorch ZIP streams
    │
    ▼
pvm.emulator       ──► stack + memo simulation, opcode handlers
    │
    ▼
domain.cfg         ──► sequential CFG + GLOBAL_LOOKUP / REDUCE / BUILD / MEMO edges
    │
    ▼
analysis.cfg_taint ──► fixed-point taint + exploit path backtrace
    │
    ▼
domain.security    ──► YAML policy: sinks, chain primitives, gadget folding
```

PickleProbe never calls `pickle.load()` on untrusted input. Analysis uses `pickletools.genops()` plus a **partial PVM** that tracks enough stack state to resolve lookups and classify invocations.

## Walkthrough: `picklescan/malicious15b.pkl`

Real sample from the [picklescan](https://github.com/mmaitre314/picklescan) reference corpus (used by Hugging Face Hub scanning).

1. **Strings on stack** — module/name literals are pushed without a `GLOBAL` opcode.
2. **`STACK_GLOBAL@27`** — resolves to `bdb.Bdb.run` (debugger hook), invisible to GLOBAL grep.
3. **`NEWOBJ` + `BUILD`** — constructs `bdb.Bdb` instance with attacker-controlled state.
4. **`REDUCE@131`** — invokes `bdb.Bdb.run` with embedded `os.system("whoami")` string in args.
5. **Policy** — `bdb.Bdb` is a chain primitive → **SUSPICIOUS**; memo-fed `STACK_GLOBAL` raises a warning.

A naive scanner that only lists `GLOBAL` imports sees no `os.system` line. PickleProbe flags the invocation chain and memo pattern.

See [docs/demo-output.txt](demo-output.txt) for full CLI output (malicious + benign side by side).

## Dual taint model

| Layer | Tracks | Purpose |
|-------|--------|---------|
| Resolution taint | Can we name the callable? (`CONST` / `MEMO` / `UNKNOWN`) | Opcode simulation fidelity |
| Security taint | Is the callable dangerous? (`CLEAN` / `SUSPICIOUS` / `SINK`) | Policy-backed verdict |

Memo slots inherit stored security on `GET` (transport, not laundering) — see [SECURITY_POLICY.md](SECURITY_POLICY.md).

## Non-goals (explicit limits)

| Limit | Why |
|-------|-----|
| Not a production scanner | Learning instrument; no sanitization, no HF integration |
| Partial PVM | Not every opcode / PyTorch layout fully modeled |
| No full PickleBall eval | 336-model Zenodo corpus is ~19 GB; we use published subsets |
| Gadget depth | Long multi-hop chains may stay `INCONCLUSIVE` |
| Static only | Findings are advisory; no auto-remediation |
| Name ≠ Fickling `polyglot` | Unrelated Trail of Bits submodule for polyglot *files* |

## Comparison to the field

| Tool | Role |
|------|------|
| [picklescan](https://github.com/mmaitre314/picklescan) | Production blocklist scanner (HF Hub) |
| [Fickling](https://github.com/trailofbits/fickling) | Decompile, analyze, sanitize |
| [PickleBall](https://github.com/columbia/pickleball) | Research enforcement via library policies |
| **PickleProbe** | Teach bytecode + CFG + taint; honest small-corpus eval |

Run `python scripts/compare_picklescan.py` when `picklescan` is installed.

## API (library use)

```python
from pickleprobe.analysis.analyzer import PickleAnalyzer

result = PickleAnalyzer(policy_path="custom.yaml").analyze_file("model.pt")
report = result.primary
print(report.sink_invocations, report.exploit_paths)
```

## Corpus philosophy

**Zero synthetic evaluation bytes.** All manifest samples are downloaded from:

- [WolfpackArmy/pytorch-pickle-rce-poc](https://huggingface.co/WolfpackArmy/pytorch-pickle-rce-poc)
- [Rodion111/pytorch-pt2-ace-poc](https://huggingface.co/Rodion111/pytorch-pt2-ace-poc)
- [mmaitre314/picklescan tests/data](https://github.com/mmaitre314/picklescan/tree/main/tests/data)

Unit tests still use inline bytecode fixtures for fast regression — those are not part of the eval corpus.

Optional full-scale eval: `./scripts/download_corpus.sh` (PickleBall Zenodo archives).
