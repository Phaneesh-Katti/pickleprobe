# Security policy SOP

Polyglot's sink list and gadget primitives live in **versioned YAML**, not hardcoded Python sets. This is how production scanners (picklescan, Fickling rules) are typically maintained.

## File layout

```
src/polyglot/policy/
  default.yaml          # bundled default — ship with releases
```

Override at runtime (future CLI flag) with a custom path.

## Rule categories

| Section | Purpose | Example |
|---------|---------|---------|
| `sinks` | Direct RCE / shell / eval targets | `os.system`, `subprocess.run` |
| `chain_primitives` | Gadget building blocks alone are not RCE | `builtins.getattr`, `functools.partial` |
| `sensitive_attrs` | Second arg to `getattr` that escalates risk | `system`, `eval` |
| `extension_codes_suspicious` | Unresolved `EXT1/2/4` opcodes | PyTorch uses extensions heavily |
| `memo_warnings` | Adversarial memo patterns | GET-before-PUT, overwrite |

## How to add a sink

1. Confirm the callable is reachable via pickle REDUCE/BUILD/NEWOBJ (not just importable).
2. Add `{ module: X, name: Y }` under `sinks`.
3. Run tests: `pytest tests/test_security_policy.py`
4. Regenerate benchmark: `python scripts/benchmark_corpus.py`

## How to add a chain primitive

1. Add under `chain_primitives`.
2. If the primitive has symbolic folding (e.g. `partial(os.system, cmd)`), extend `simulate_reduce_result` in `domain/security.py`.
3. Add a unit test in `tests/test_gadget_chains.py`.

## Severity model

| Label | Meaning |
|-------|---------|
| `CLEAN` | Known-safe resolved target |
| `INCONCLUSIVE` | Unresolved callable/args — not proven safe |
| `SUSPICIOUS` | Chain primitive or shady pattern |
| `SINK` | Known dangerous callable or proven derivative |

Policy YAML defines **what** is dangerous. `simulate_reduce_result` defines **how** gadgets compose.

## Maintenance cadence

- **CVE / PoC**: add sink + corpus sample + manifest entry same PR.
- **Quarterly**: diff against [picklescan global definitions](https://github.com/mmaitre314/picklescan) and Trail of Bits Fickling lists.
- **Per deployment**: fork `default.yaml` to allowlist ML stack modules (`torch`, `numpy`) if you accept those globals in your pipeline.

## Do not

- Put secrets in policy files.
- Mark broad modules as sinks (`os` module itself is not a callable).
- Assume a longer list means better detection — each rule needs a test or corpus reference.
