from __future__ import annotations

from datetime import UTC, datetime

import pytest
from conftest import openssl_accepts, real, root

from rodmena_rfc3161 import TimestampError, parse_response, verify

CASES = real()


def test_every_authority_is_represented() -> None:
    assert {c[0] for c in CASES} == {"digicert", "sectigo", "freetsa"}


@pytest.mark.parametrize(("name", "reply", "digest", "nonce"), CASES)
def test_real_tokens_verify_natively_and_agree_with_openssl(
    name: str, reply: bytes, digest: bytes, nonce: int
) -> None:
    info = verify(parse_response(reply), digest, [root(name)], nonce=nonce)
    assert info.digest == digest and info.nonce == nonce
    assert datetime(2026, 1, 1, tzinfo=UTC) < info.gen_time < datetime(2100, 1, 1, tzinfo=UTC)
    assert openssl_accepts(reply, digest, root(name))


@pytest.mark.parametrize(("name", "reply", "digest", "nonce"), CASES)
def test_a_real_token_fails_under_the_wrong_root_digest_or_nonce(
    name: str, reply: bytes, digest: bytes, nonce: int
) -> None:
    token = parse_response(reply)
    other = {"digicert": "sectigo", "sectigo": "freetsa", "freetsa": "digicert"}[name]
    with pytest.raises(TimestampError):
        verify(token, digest, [root(other)])
    assert not openssl_accepts(reply, digest, root(other))
    wrong = bytes([digest[0] ^ 1]) + digest[1:]
    with pytest.raises(TimestampError):
        verify(token, wrong, [root(name)])
    assert not openssl_accepts(reply, wrong, root(name))
    with pytest.raises(TimestampError):
        verify(token, digest, [root(name)], nonce=nonce + 1)
