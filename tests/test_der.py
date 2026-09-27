from __future__ import annotations

import pytest

from rodmena_rfc3161 import der
from rodmena_rfc3161.errors import TimestampError


@pytest.mark.parametrize(
    "data",
    [
        b"\x30\x80\x02\x01\x01\x00\x00",
        b"\x30\x05\x02\x01\x01",
        b"\x04\x81\x05hello",
        b"\x04\x02ab\x00",
        b"\x02\x02\x00\x01",
        b"\x1f\x80\x01\x00",
        b"\x30",
        b"",
    ],
)
def test_strict_reading_refuses_bad_encodings(data: bytes) -> None:
    with pytest.raises(TimestampError):
        der.read_integer(der.parse(data)) if data[:1] == b"\x02" else der.parse(data)


def test_ber_allows_indefinite_lengths_only_when_asked() -> None:
    data = b"\x30\x80\x02\x01\x01\x00\x00"
    assert der.read_integer(der.parse(data, ber=True).children(ber=True)[0]) == 1
    with pytest.raises(TimestampError):
        der.parse(b"\x04\x80ab\x00\x00", ber=True)


def _walk(node: der.Node, depth: int = 0) -> None:
    if node.constructed:
        for child in node.children(depth=depth):
            _walk(child, depth + 1)


def test_depth_and_size_are_capped() -> None:
    nested = b"\x05\x00"
    for _ in range(der.MAX_DEPTH + 2):
        nested = der.tlv(0x30, nested)
    with pytest.raises(TimestampError, match="deep"):
        _walk(der.parse(nested))
    shallow = b"\x05\x00"
    for _ in range(der.MAX_DEPTH - 2):
        shallow = der.tlv(0x30, shallow)
    _walk(der.parse(shallow))
    with pytest.raises(TimestampError, match="large"):
        der.parse(der.tlv(0x04, b"a" * (der.MAX_INPUT + 1)))


def test_round_trips() -> None:
    for value in (0, 1, 127, 128, 255, 256, 2**63 - 1):
        assert der.read_integer(der.parse(der.integer(value))) == value
    for dotted in ("1.2.840.113549.1.9.16.1.4", "2.16.840.1.101.3.4.2.1", "2.999.3"):
        assert der.read_oid(der.parse(der.oid(dotted))) == dotted


def test_der_refuses_constructed_primitives_and_constructed_null_parameters() -> None:
    with pytest.raises(TimestampError, match="constructed"):
        der.parse(b"\x22\x03\x02\x01\x01")
    assert der.parse(b"\x24\x03\x04\x01a", ber=True).constructed
    from rodmena_rfc3161 import tsp

    with pytest.raises(TimestampError, match="constructed|NULL"):
        tsp.algorithm(
            der.parse(b"\x30\x0d" + der.oid("1.2.840.113549.1.1.11") + b"\x25\x00", ber=True)
        )
