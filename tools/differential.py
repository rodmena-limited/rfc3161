from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from conftest import openssl_accepts, root  # noqa: E402

from rodmena_rfc3161 import TimestampError, parse_response, tsp, verify  # noqa: E402

OTHER = {"digicert": "sectigo", "sectigo": "freetsa", "freetsa": "digicert"}


def _flip(data: bytes, inner: bytes, fraction: float) -> bytes:
    at = data.index(inner) + int(len(inner) * fraction)
    return data[:at] + bytes([data[at] ^ 0x01]) + data[at + 1 :]


def _ours(reply: bytes, digest: bytes, name: str) -> bool:
    try:
        verify(parse_response(reply), digest, [root(name)])
    except TimestampError:
        return False
    return True


def variants(name: str, reply: bytes, digest: bytes) -> list[tuple[str, bytes, bytes, str]]:
    signed = tsp.signed_data(parse_response(reply))
    wrong = bytes([digest[0] ^ 1]) + digest[1:]
    return [
        ("original", reply, digest, name),
        ("signature", _flip(reply, signed.signer.signature, 0.5), digest, name),
        ("tstinfo", _flip(reply, signed.content, 0.9), digest, name),
        ("signed_attrs", _flip(reply, signed.signer.signed_attrs.content, 0.5), digest, name),
        ("wrong_digest", reply, wrong, name),
        ("wrong_root", reply, digest, OTHER[name]),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    counts: Counter[str] = Counter()
    disagreements: list[str] = []
    for meta_path in sorted(args.folder.glob("*.json")):
        meta = json.loads(meta_path.read_text())
        reply = meta_path.with_suffix(".tsr").read_bytes()
        name = meta["authority"]
        for kind, data, digest, ca_name in variants(name, reply, bytes.fromhex(meta["digest"])):
            ours = _ours(data, digest, ca_name)
            theirs = openssl_accepts(data, digest, root(ca_name))
            counts[f"{name} {kind} {'accept' if ours else 'reject'}"] += 1
            if ours != theirs:
                disagreements.append(f"{meta_path.name} {kind}: ours {ours}, openssl {theirs}")
    print(
        json.dumps(
            {"counts": dict(sorted(counts.items())), "disagreements": disagreements}, indent=2
        )
    )
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
