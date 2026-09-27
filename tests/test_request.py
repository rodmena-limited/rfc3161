from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest

from rodmena_rfc3161 import TimestampError, build_request


def test_openssl_reads_our_request() -> None:
    digest = bytes(range(32))
    request = build_request(digest, "sha256", nonce=0x1234)
    with tempfile.TemporaryDirectory() as folder:
        Path(folder, "q.tsq").write_bytes(request)
        text = subprocess.run(  # noqa: S603
            ["openssl", "ts", "-query", "-in", str(Path(folder, "q.tsq")), "-text"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    assert "Hash Algorithm: sha256" in text and "Nonce: 0x1234" in text
    assert "Certificate required: yes" in text
    assert "00 01 02 03" in text.replace("-", " ")


def test_a_digest_of_the_wrong_length_is_refused() -> None:
    with pytest.raises(TimestampError):
        build_request(b"short", "sha256")
