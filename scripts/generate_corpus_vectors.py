#!/usr/bin/env python3
"""Generate hand-picked pickle bytecode vectors (no pickle.load on malicious output)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "tests" / "corpus" / "samples"

# getattr(__import__('os'), 'system') chain — no GLOBAL os.system
GETATTR_GADGET = (
    b"cbuiltins\n__import__\n"
    b"(S'os'\n"
    b"tR"
    b"p0\n"
    b"cbuiltins\ngetattr\n"
    b"(g0\n"
    b"S'system'\n"
    b"tR."
)

# functools.partial(os.system) then invoke — partial folding
PARTIAL_GADGET = (
    b"cfunctools\npartial\n"
    b"(cos\n"
    b"system\n"
    b"tR"
    b"p0\n"
    b"(S'id'\n"
    b"tR."
)

# Direct builtins.eval sink (different sink family)
GLOBAL_EVAL = b"cbuiltins\neval\n(S'1+1'\ntR."

# operator.methodcaller — suspicious, not sink alone
METHODCALLER = (
    b"coperator\nmethodcaller\n"
    b"(S'system'\n"
    b"S'id'\n"
    b"tR."
)


def write_benign() -> None:
    import pickle

    dest = DEST / "benign/raw"
    dest.mkdir(parents=True, exist_ok=True)
    pickle.dump([1, 2, 3, 4], open(dest / "list_protocol4.pkl", "wb"), protocol=4)
    pickle.dump(frozenset([1, 2]), open(dest / "set_protocol4.pkl", "wb"), protocol=4)


def write_malicious() -> None:
    dest = DEST / "malicious/raw"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "getattr_import_gadget.pkl").write_bytes(GETATTR_GADGET)
    (dest / "partial_os_system.pkl").write_bytes(PARTIAL_GADGET)
    (dest / "global_eval.pkl").write_bytes(GLOBAL_EVAL)
    (dest / "methodcaller_suspicious.pkl").write_bytes(METHODCALLER)


def main() -> None:
    write_benign()
    write_malicious()
    print(f"Wrote corpus vectors under {DEST}")


if __name__ == "__main__":
    main()
