from __future__ import annotations

import os

import pytest
from conftest import openssl_accepts, real, root
from forge import Authority, response, token, tst_info

from rodmena_rfc3161 import TimestampError, parse_response, tsp, verify

DIGEST = os.urandom(32)


def _both(reply: bytes, authority: Authority, digest: bytes = DIGEST) -> tuple[bool, bool]:
    try:
        verify(parse_response(reply), digest, [authority.root])
        ours = True
    except TimestampError:
        ours = False
    return ours, openssl_accepts(reply, digest, authority.root)


def test_the_forged_known_positive_passes_both() -> None:
    authority = Authority()
    assert _both(response(token(authority, tst_info(DIGEST, 7))), authority) == (True, True)


def test_a_flipped_signature_byte_fails_both() -> None:
    authority = Authority()
    good = token(authority, tst_info(DIGEST, 7))
    signed = tsp.signed_data(good)
    at = good.rindex(signed.signer.signature) + 10
    bad = good[:at] + bytes([good[at] ^ 1]) + good[at + 1 :]
    assert _both(response(bad), authority) == (False, False)


def test_a_tampered_tstinfo_fails_both() -> None:
    authority = Authority()
    content = tst_info(DIGEST, 7)
    good = token(authority, content)
    at = good.index(content) + len(content) - 3
    bad = good[:at] + bytes([good[at] ^ 1]) + good[at + 1 :]
    assert _both(response(bad), authority) == (False, False)


def test_unsorted_signed_attributes_are_refused() -> None:
    authority = Authority()
    reply = response(token(authority, tst_info(DIGEST, 7), unsorted_attrs=True))
    with pytest.raises(TimestampError, match="not DER"):
        verify(parse_response(reply), DIGEST, [authority.root])


def test_a_signer_without_the_critical_timestamping_eku_is_refused() -> None:
    for eku in ("none", "noncritical"):
        authority = Authority(eku=eku)
        reply = response(token(authority, tst_info(DIGEST, 7)))
        assert _both(reply, authority) == (False, False), eku


def test_nonce_and_status_are_enforced() -> None:
    authority = Authority()
    reply = response(token(authority, tst_info(DIGEST, 7)))
    verify(parse_response(reply), DIGEST, [authority.root], nonce=7)
    with pytest.raises(TimestampError, match="nonce"):
        verify(parse_response(reply), DIGEST, [authority.root], nonce=8)
    with pytest.raises(TimestampError, match="not granted"):
        parse_response(response(token(authority, tst_info(DIGEST, 7)), status=2))


def test_an_unrelated_root_is_refused_for_a_forged_token() -> None:
    authority = Authority()
    reply = response(token(authority, tst_info(DIGEST, 7)))
    with pytest.raises(TimestampError):
        verify(parse_response(reply), DIGEST, [Authority().root])


def test_a_real_token_with_a_flipped_signed_attribute_fails_both() -> None:
    name, reply, digest, _ = real()[0]
    signed = tsp.signed_data(parse_response(reply))
    attrs = signed.signer.signed_attrs.content
    at = reply.index(attrs) + len(attrs) // 2
    bad = reply[:at] + bytes([reply[at] ^ 1]) + reply[at + 1 :]
    with pytest.raises(TimestampError):
        verify(parse_response(bad), digest, [root(name)])
    assert not openssl_accepts(bad, digest, root(name))
