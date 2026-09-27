from __future__ import annotations

import json
import os

import pytest
from conftest import FIXTURES, openssl_accepts, root
from forge import Authority, response, token, tst_info

from rodmena_rfc3161 import TimestampError, der, parse_response, verify

DIGEST = os.urandom(32)


@pytest.mark.parametrize(
    ("data", "ber"),
    [
        (b"\x01\x00", False),
        (b"\x01\x02\xff\xff", False),
        (b"\x01\x01\x01", False),
        (b"\x01\x00", True),
        (b"\x05\x01\x00", False),
        (b"\x05\x01\x00", True),
        (b"\x02\x00", True),
        (b"\x02\x02\x00\x7f", True),
        (b"\x06\x00", True),
        (b"\x06\x02\x80\x01", True),
        (b"\x06\x01\x81", True),
        (b"\x03\x00", True),
        (b"\x03\x02\x08\x00", True),
        (b"\x03\x01\x03", True),
        (b"\x03\x02\x03\x01", False),
        (b"\x17\x0d260927023013X", True),
        (b"\x18\x0f2026092702301Z3", True),
        (b"\x18\x1120260927023013.0Z", True),
        (b"\x10\x00", True),
        (b"\x00\x00", False),
    ],
)
def test_every_universal_primitive_obeys_its_content_rules(data: bytes, ber: bool) -> None:
    with pytest.raises(TimestampError):
        der.parse(data, ber=ber)


@pytest.mark.parametrize(
    "data",
    [b"\x01\x01\xff", b"\x05\x00", b"\x02\x01\x80", b"\x06\x03\x2a\x86\x48", b"\x03\x02\x03\x08"],
)
def test_valid_primitives_still_read(data: bytes) -> None:
    der.parse(data)


MALFORMED = [der.tlv(0x01, b""), der.tlv(0x25, b"")]
FOREIGN = [der.boolean(True), der.integer(0)]


def _reply(authority: Authority, field: str, params: bytes) -> bytes:
    content = tst_info(DIGEST, 7, imprint_params=params if field == "imprint" else None)
    return response(
        token(
            authority,
            content,
            signature_params=params if field == "signature" else None,
            digest_params=params if field == "digest" else None,
            listed_params=params if field == "listed" else None,
        )
    )


@pytest.mark.parametrize("field", ["signature", "digest", "listed", "imprint"])
@pytest.mark.parametrize("params", MALFORMED)
def test_malformed_algorithm_parameters_are_refused_by_both(field: str, params: bytes) -> None:
    authority = Authority()
    reply = _reply(authority, field, params)
    with pytest.raises(TimestampError):
        verify(parse_response(reply), DIGEST, [authority.root])
    assert not openssl_accepts(reply, DIGEST, authority.root)


@pytest.mark.parametrize("field", ["signature", "digest", "listed", "imprint"])
@pytest.mark.parametrize("params", FOREIGN)
def test_well_formed_foreign_parameters_are_refused_where_openssl_is_lenient(
    field: str, params: bytes
) -> None:
    authority = Authority()
    with pytest.raises(TimestampError, match="parameters"):
        verify(parse_response(_reply(authority, field, params)), DIGEST, [authority.root])


def test_absent_parameters_are_accepted_for_rsa_and_hashes() -> None:
    authority = Authority()
    reply = response(
        token(
            authority,
            tst_info(DIGEST, 7, imprint_params=b""),
            signature_params=b"",
            digest_params=b"",
            listed_params=b"",
        )
    )
    verify(parse_response(reply), DIGEST, [authority.root], nonce=7)
    assert openssl_accepts(reply, DIGEST, authority.root)


@pytest.mark.parametrize("case", ["fuzz-918273-49909", "fuzz-777001-31839", "fuzz-60601-72217"])
def test_fuzz_regressions_are_refused_by_both(case: str) -> None:
    path = FIXTURES / "regression" / case
    meta = json.loads(path.with_suffix(".json").read_text())
    reply = path.with_suffix(".tsr").read_bytes()
    digest = bytes.fromhex(meta["digest"])
    with pytest.raises(TimestampError):
        verify(parse_response(reply), digest, [root(meta["authority"])], nonce=meta["nonce"])
    assert not openssl_accepts(reply, digest, root(meta["authority"]))


def test_a_certificate_name_value_must_be_a_directory_string() -> None:
    authority = Authority()
    good = response(token(authority, tst_info(DIGEST, 7), stranger=True))
    verify(parse_response(good), DIGEST, [authority.root], nonce=7)
    assert openssl_accepts(good, DIGEST, authority.root)
    candidates = [der.tlv(tag, b"stranger cross") for tag in (0x0C, 0x13)]
    source = next(c for c in candidates if c in good)
    bad = good.replace(source, der.tlv(0x04, b"stranger cross"), 1)
    with pytest.raises(TimestampError):
        verify(parse_response(bad), DIGEST, [authority.root])
    assert not openssl_accepts(bad, DIGEST, authority.root)
