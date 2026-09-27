from __future__ import annotations

import argparse
import json
import random
import signal
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from types import FrameType

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from conftest import openssl_accepts, real, root  # noqa: E402

from rodmena_rfc3161 import TimestampError, parse_response, verify  # noqa: E402


@dataclass
class Report:
    cases: int
    seed: int
    outcomes: dict[str, int]
    problems: list[dict[str, object]]


class Hang(Exception):
    pass


def _alarm(_signum: int, _frame: FrameType | None) -> None:
    raise Hang


def mutate(data: bytes, rng: random.Random) -> bytes:
    kind = rng.randrange(6)
    buf = bytearray(data)
    if kind == 0:
        for _ in range(rng.randint(1, 4)):
            at = rng.randrange(len(buf))
            buf[at] ^= 1 << rng.randrange(8)
    elif kind == 1:
        for _ in range(rng.randint(1, 4)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
    elif kind == 2:
        return bytes(buf[: rng.randrange(len(buf))])
    elif kind == 3:
        at = rng.randrange(len(buf))
        buf[at:at] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
    elif kind == 4:
        at, size = rng.randrange(len(buf)), rng.randint(1, 64)
        buf[at:at] = buf[at : at + size]
    else:
        at = rng.randrange(len(buf))
        del buf[at : at + rng.randint(1, 16)]
    return bytes(buf)


def run(cases: int, seed: int, timeout_s: int = 2) -> Report:
    rng = random.Random(seed)
    corpus = real()
    counts: Counter[str] = Counter()
    problems: list[dict[str, object]] = []
    signal.signal(signal.SIGALRM, _alarm)
    for index in range(cases):
        name, reply, digest, nonce = corpus[index % len(corpus)]
        mutated = mutate(reply, rng)
        signal.alarm(timeout_s)
        try:
            verify(parse_response(mutated), digest, [root(name)], nonce=nonce)
            outcome = "accepted"
        except TimestampError:
            outcome = "rejected"
        except Hang:
            outcome = "hang"
        except Exception as exc:  # noqa: BLE001
            outcome = f"raised {type(exc).__name__}"
        finally:
            signal.alarm(0)
        if outcome == "accepted":
            outcome = (
                "accepted, openssl agrees"
                if openssl_accepts(mutated, digest, root(name))
                else "accepted, openssl REJECTS"
            )
        counts[outcome] += 1
        if outcome not in ("rejected", "accepted, openssl agrees") and len(problems) < 20:
            problems.append({"case": index, "outcome": outcome, "authority": name})
    return Report(cases, seed, dict(counts), problems)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=3161)
    args = parser.parse_args()
    report = run(args.cases, args.seed)
    print(json.dumps(asdict(report), indent=2))
    bad = set(report.outcomes) - {"rejected", "accepted, openssl agrees"}
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
