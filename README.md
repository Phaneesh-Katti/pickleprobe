# Polyglot

Static analyzer for Python pickle bytecode. Inspects serialized objects **without** calling `pickle.load()`, using `pickletools` opcode disassembly plus a partial Pickle Virtual Machine (PVM) emulator.

## Current scope

- **PVM emulation**: stack, memo, protocol 0–5 opcodes including `SETITEMS`/`APPENDS`/`ADDITEMS`, `EXT*`, `INST`/`OBJ`, `PERSID`
- **Security policy**: versioned YAML rule pack (`src/polyglot/policy/default.yaml`) — see [docs/SECURITY_POLICY.md](docs/SECURITY_POLICY.md)
- **Invocation analysis**: `GLOBAL`, `STACK_GLOBAL`, `REDUCE`, `BUILD`, `NEWOBJ` with gadget folding (`getattr`, `partial`, `methodcaller`, …)
- **CFG + taint propagation**: dataflow edges and exploit path reporting
- **Formats**: raw pickle and PyTorch `.pt` ZIP extraction
- **Memo adversarial checks**: GET-before-PUT, overwrite PUT, memo-fed `STACK_GLOBAL`

## Project layout

```
src/polyglot/
  domain/       Values, CFG, security policy loader
  policy/       default.yaml rule pack
  pvm/          Pickle VM emulator
  analysis/     Analyzer, CFG taint propagation
  formats/      PyTorch ZIP / raw pickle loading
  cli.py        Command-line entry point
tests/corpus/   Curated samples + manifest.yaml
docs/           SECURITY_POLICY.md, COMPARISON.md
```

## Setup

```bash
python3 -m venv polyglot
source polyglot/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
polyglot analyze path/to/suspicious.pkl
polyglot analyze path/to/model.pt --json
```

Exit codes: `0` clean, `1` suspicious/inconclusive findings, `2` SINK detected.

## Run tests

```bash
pytest
python scripts/benchmark_corpus.py
```

## Evaluation corpus

See [tests/corpus/README.md](tests/corpus/README.md). Refresh with `./scripts/fetch_curated_corpus.sh`.
