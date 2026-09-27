from __future__ import annotations

from dataclasses import dataclass

from .errors import TimestampError

MAX_INPUT = 1 << 20
MAX_DEPTH = 32

UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 0, 1, 2, 3
BOOLEAN = 1
INTEGER = 2
BIT_STRING = 3
OCTET_STRING = 4
NULL = 5
OID = 6
SEQUENCE = 16
SET = 17
GENERALIZED_TIME = 24


@dataclass(frozen=True, slots=True)
class Node:
    cls: int
    constructed: bool
    number: int
    header: bytes
    content: bytes
    raw: bytes
    definite: bool

    def children(self, *, ber: bool = False, depth: int = 0) -> list[Node]:
        if not self.constructed:
            raise TimestampError("expected a constructed value")
        return read_all(self.content, ber=ber, depth=depth + 1)

    def is_(self, number: int, cls: int = UNIVERSAL) -> bool:
        return self.cls == cls and self.number == number


def _read_tag(data: bytes, pos: int) -> tuple[int, bool, int, int]:
    if pos >= len(data):
        raise TimestampError("truncated tag")
    first = data[pos]
    cls = first >> 6
    constructed = bool(first & 0x20)
    number = first & 0x1F
    pos += 1
    if number == 0x1F:
        number = 0
        for count in range(5):
            if pos >= len(data):
                raise TimestampError("truncated tag")
            byte = data[pos]
            pos += 1
            if count == 0 and byte == 0x80:
                raise TimestampError("non-minimal tag")
            number = (number << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
        else:
            raise TimestampError("tag number too large")
        if number < 0x1F:
            raise TimestampError("non-minimal tag")
    return cls, constructed, number, pos


def _read_length(data: bytes, pos: int, ber: bool) -> tuple[int | None, int]:
    if pos >= len(data):
        raise TimestampError("truncated length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    if first == 0x80:
        if not ber:
            raise TimestampError("indefinite length")
        return None, pos
    count = first & 0x7F
    if count > 4 or pos + count > len(data):
        raise TimestampError("bad length")
    length = int.from_bytes(data[pos : pos + count], "big")
    if not ber and (length < 0x80 or data[pos] == 0):
        raise TimestampError("non-minimal length")
    return length, pos + count


def _end_of_contents(data: bytes, pos: int, ber: bool, depth: int) -> int:
    while True:
        if pos + 2 > len(data):
            raise TimestampError("unterminated indefinite length")
        if data[pos] == 0 and data[pos + 1] == 0:
            return pos
        _, pos = read_one(data, pos, ber=ber, depth=depth + 1)


def read_one(data: bytes, pos: int = 0, *, ber: bool = False, depth: int = 0) -> tuple[Node, int]:
    if depth > MAX_DEPTH:
        raise TimestampError("nesting too deep")
    if len(data) > MAX_INPUT:
        raise TimestampError("input too large")
    start = pos
    cls, constructed, number, pos = _read_tag(data, pos)
    length, pos = _read_length(data, pos, ber)
    header = data[start:pos]
    if length is None:
        if not constructed:
            raise TimestampError("indefinite length on a primitive value")
        end = _end_of_contents(data, pos, ber, depth)
        node = Node(cls, constructed, number, header, data[pos:end], data[start : end + 2], False)
        return node, end + 2
    end = pos + length
    if end > len(data):
        raise TimestampError("length runs past the end")
    return Node(cls, constructed, number, header, data[pos:end], data[start:end], True), end


def read_all(data: bytes, *, ber: bool = False, depth: int = 0) -> list[Node]:
    nodes: list[Node] = []
    pos = 0
    while pos < len(data):
        node, pos = read_one(data, pos, ber=ber, depth=depth)
        nodes.append(node)
    return nodes


def parse(data: bytes, *, ber: bool = False) -> Node:
    node, end = read_one(data, ber=ber)
    if end != len(data):
        raise TimestampError("trailing data")
    return node


def length_bytes(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + length_bytes(len(content)) + content


def sequence(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(items: list[bytes]) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))


def integer(value: int) -> bytes:
    if value < 0:
        raise TimestampError("only non-negative INTEGERs are encoded")
    return tlv(INTEGER, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def octet_string(value: bytes) -> bytes:
    return tlv(OCTET_STRING, value)


def boolean(value: bool) -> bytes:
    return tlv(BOOLEAN, b"\xff" if value else b"\x00")


def null() -> bytes:
    return tlv(NULL, b"")


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    if len(parts) < 2 or parts[0] > 2 or (parts[0] < 2 and parts[1] > 39):
        raise TimestampError("bad object identifier")
    body = bytearray()
    for value in [parts[0] * 40 + parts[1], *parts[2:]]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        body.extend(reversed(chunk))
    return tlv(OID, bytes(body))


def read_integer(node: Node) -> int:
    if not node.is_(INTEGER) or node.constructed:
        raise TimestampError("expected an INTEGER")
    return integer_value(node.content)


def integer_value(content: bytes) -> int:
    if not content:
        raise TimestampError("empty INTEGER")
    if len(content) > 1 and (
        (content[0] == 0 and not content[1] & 0x80) or (content[0] == 0xFF and content[1] & 0x80)
    ):
        raise TimestampError("non-minimal INTEGER")
    return int.from_bytes(content, "big", signed=True)


def read_oid(node: Node) -> str:
    if not node.is_(OID) or node.constructed or not node.content:
        raise TimestampError("expected an OBJECT IDENTIFIER")
    values: list[int] = []
    value = 0
    fresh = True
    for byte in node.content:
        if fresh and byte == 0x80:
            raise TimestampError("non-minimal OBJECT IDENTIFIER")
        value = (value << 7) | (byte & 0x7F)
        fresh = not byte & 0x80
        if fresh:
            values.append(value)
            value = 0
    if not fresh:
        raise TimestampError("truncated OBJECT IDENTIFIER")
    first = min(values[0] // 40, 2)
    return ".".join(str(v) for v in [first, values[0] - 40 * first, *values[1:]])


def read_octets(node: Node) -> bytes:
    if not node.is_(OCTET_STRING) or node.constructed:
        raise TimestampError("expected an OCTET STRING")
    return node.content


def read_boolean(node: Node) -> bool:
    if not node.is_(BOOLEAN) or node.constructed or len(node.content) != 1:
        raise TimestampError("expected a BOOLEAN")
    if node.content not in (b"\x00", b"\xff"):
        raise TimestampError("non-DER BOOLEAN")
    return node.content == b"\xff"
