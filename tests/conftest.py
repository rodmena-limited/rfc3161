from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

FIXTURES = Path(__file__).parent / "fixtures"


def root(name: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate((FIXTURES / f"{name}-root.pem").read_bytes())


def real() -> list[tuple[str, bytes, bytes, int]]:
    found = []
    for tsr in sorted(FIXTURES.glob("*-[0-9][0-9][0-9].tsr")):
        meta = json.loads(tsr.with_suffix(".json").read_text())
        found.append(
            (meta["authority"], tsr.read_bytes(), bytes.fromhex(meta["digest"]), meta["nonce"])
        )
    return found


def openssl_accepts(response: bytes, digest: bytes, ca: x509.Certificate) -> bool:
    with tempfile.TemporaryDirectory() as folder:
        Path(folder, "r.tsr").write_bytes(response)
        Path(folder, "ca.pem").write_bytes(ca.public_bytes(Encoding.PEM))
        done = subprocess.run(  # noqa: S603
            [
                "openssl",
                "ts",
                "-verify",
                "-digest",
                digest.hex(),
                "-in",
                str(Path(folder, "r.tsr")),
                "-CAfile",
                str(Path(folder, "ca.pem")),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    return "Verification: OK" in done.stdout
