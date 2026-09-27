from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from pathlib import Path

from rodmena_rfc3161 import build_request, new_nonce

AUTHORITIES = {
    "digicert": "http://timestamp.digicert.com",
    "sectigo": "http://timestamp.sectigo.com",
    "freetsa": "https://freetsa.org/tsr",
}


def stamp(url: str, digest: bytes, nonce: int) -> bytes:
    request = urllib.request.Request(  # noqa: S310
        url,
        data=build_request(digest, "sha256", nonce),
        headers={"Content-Type": "application/timestamp-query"},
    )
    with urllib.request.urlopen(request, timeout=30) as answer:  # noqa: S310
        return bytes(answer.read())


def main(argv: list[str]) -> int:
    out = Path(argv[0])
    count = int(argv[1])
    names = argv[2:] or list(AUTHORITIES)
    out.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        for name in names:
            digest = os.urandom(32)
            nonce = new_nonce()
            reply = stamp(AUTHORITIES[name], digest, nonce)
            base = out / f"{name}-{index:03d}"
            base.with_suffix(".tsr").write_bytes(reply)
            base.with_suffix(".json").write_text(
                json.dumps({"digest": digest.hex(), "nonce": nonce, "authority": name})
            )
            time.sleep(15)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
