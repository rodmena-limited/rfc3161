from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from . import der
from .der import CONTEXT, Node
from .errors import TimestampError

SIGNED_DATA = "1.2.840.113549.1.7.2"
TST_INFO = "1.2.840.113549.1.9.16.1.4"
CONTENT_TYPE = "1.2.840.113549.1.9.3"
MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"


@dataclass(frozen=True, slots=True)
class Algorithm:
    oid: str
    parameters: Node | None


@dataclass(frozen=True, slots=True)
class SignerInfo:
    issuer: bytes | None
    serial: int | None
    key_id: bytes | None
    digest_algorithm: Algorithm
    signed_attrs: Node
    signature_algorithm: Algorithm
    signature: bytes


@dataclass(frozen=True, slots=True)
class SignedData:
    content_type: str
    content: bytes
    certificates: list[bytes]
    signer: SignerInfo
    digest_algorithms: list[str]


@dataclass(frozen=True, slots=True)
class TstInfo:
    policy: str
    hash_algorithm: Algorithm
    hashed_message: bytes
    serial: int
    gen_time: datetime
    accuracy_micros: int | None
    ordering: bool
    nonce: int | None


def expect(node: Node, number: int, what: str, cls: int = der.UNIVERSAL) -> Node:
    if not node.is_(number, cls):
        raise TimestampError(f"expected {what}")
    return node


def algorithm(node: Node) -> Algorithm:
    parts = expect(node, der.SEQUENCE, "an AlgorithmIdentifier").children()
    if not 1 <= len(parts) <= 2:
        raise TimestampError("bad AlgorithmIdentifier")
    params = parts[1] if len(parts) == 2 else None
    if params is not None and params.is_(der.NULL) and params.content:
        raise TimestampError("bad NULL parameters")
    return Algorithm(der.read_oid(parts[0]), params)


def response_status(data: bytes) -> tuple[int, bytes | None]:
    parts = expect(der.parse(data, ber=True), der.SEQUENCE, "a TimeStampResp").children(ber=True)
    if not 1 <= len(parts) <= 2:
        raise TimestampError("bad TimeStampResp")
    info = expect(parts[0], der.SEQUENCE, "a PKIStatusInfo").children(ber=True)
    if not info:
        raise TimestampError("empty PKIStatusInfo")
    status = der.read_integer(info[0])
    token = parts[1].raw if len(parts) == 2 else None
    return status, token


def _attrs(node: Node, unsigned: bool = False) -> dict[str, list[Node]]:
    found: dict[str, list[Node]] = {}
    for attr in node.children(ber=unsigned):
        pair = expect(attr, der.SEQUENCE, "an Attribute").children()
        if len(pair) != 2:
            raise TimestampError("bad Attribute")
        name = der.read_oid(pair[0])
        if name in found and not unsigned:
            raise TimestampError("repeated signed attribute")
        values = expect(pair[1], der.SET, "attribute values").children(ber=unsigned)
        if not values:
            raise TimestampError("an attribute has no values")
        found[name] = values
    return found


def signed_attributes(info: SignerInfo) -> dict[str, list[Node]]:
    return _attrs(info.signed_attrs)


def _signer(node: Node) -> SignerInfo:
    parts = expect(node, der.SEQUENCE, "a SignerInfo").children(ber=True)
    if len(parts) < 5:
        raise TimestampError("short SignerInfo")
    version = der.read_integer(parts[0])
    sid = parts[1]
    issuer = serial = key_id = None
    if version == 1 and sid.is_(der.SEQUENCE):
        pair = sid.children()
        if len(pair) != 2:
            raise TimestampError("bad IssuerAndSerialNumber")
        issuer = expect(pair[0], der.SEQUENCE, "an issuer Name").raw
        serial = der.read_integer(pair[1])
    elif version == 3 and sid.is_(0, CONTEXT) and not sid.constructed:
        key_id = sid.content
    else:
        raise TimestampError("unsupported SignerIdentifier")
    rest = parts[3:]
    if not rest or not rest[0].is_(0, CONTEXT) or not rest[0].constructed:
        raise TimestampError("signed attributes are required")
    signed = rest[0]
    if not signed.definite:
        raise TimestampError("signed attributes are not DER")
    if len(rest) < 3:
        raise TimestampError("short SignerInfo")
    signature = der.read_octets(rest[2])
    for extra in rest[3:]:
        if not extra.is_(1, CONTEXT) or not extra.constructed:
            raise TimestampError("unexpected field in SignerInfo")
        _attrs(extra, unsigned=True)
    return SignerInfo(
        issuer, serial, key_id, algorithm(parts[2]), signed, algorithm(rest[1]), signature
    )


def signed_data(token: bytes) -> SignedData:
    info = expect(der.parse(token, ber=True), der.SEQUENCE, "a ContentInfo").children(ber=True)
    if len(info) != 2 or der.read_oid(info[0]) != SIGNED_DATA:
        raise TimestampError("not a SignedData ContentInfo")
    wrapper = expect(info[1], 0, "explicit content", CONTEXT).children(ber=True)
    if len(wrapper) != 1:
        raise TimestampError("bad content wrapper")
    parts = expect(wrapper[0], der.SEQUENCE, "a SignedData").children(ber=True)
    if len(parts) < 4:
        raise TimestampError("short SignedData")
    der.read_integer(parts[0])
    digests = [
        algorithm(a).oid for a in expect(parts[1], der.SET, "digest algorithms").children(ber=True)
    ]
    encap = expect(parts[2], der.SEQUENCE, "encapsulated content").children(ber=True)
    if len(encap) != 2:
        raise TimestampError("no encapsulated content")
    content_type = der.read_oid(encap[0])
    holder = expect(encap[1], 0, "explicit eContent", CONTEXT).children(ber=True)
    if len(holder) != 1:
        raise TimestampError("bad eContent")
    content = _octets(holder[0])
    certificates: list[bytes] = []
    signers: list[Node] = []
    for field in parts[3:]:
        if field.is_(0, CONTEXT) and field.constructed:
            certificates = [
                expect(c, der.SEQUENCE, "an X.509 certificate").raw
                for c in field.children(ber=True)
            ]
        elif field.is_(1, CONTEXT) and field.constructed:
            for crl in field.children(ber=True):
                expect(crl, der.SEQUENCE, "a revocation list").children(ber=True)
        elif field.is_(der.SET):
            signers = field.children(ber=True)
        else:
            raise TimestampError("unexpected field in SignedData")
    if len(signers) != 1:
        raise TimestampError("exactly one SignerInfo is required")
    return SignedData(content_type, content, certificates, _signer(signers[0]), digests)


def _octets(node: Node) -> bytes:
    if node.is_(der.OCTET_STRING) and not node.constructed:
        return node.content
    if node.is_(der.OCTET_STRING) and node.constructed:
        return b"".join(_octets(child) for child in node.children(ber=True))
    raise TimestampError("expected an OCTET STRING")


def _time(node: Node) -> datetime:
    if not node.is_(der.GENERALIZED_TIME) or node.constructed:
        raise TimestampError("expected a GeneralizedTime")
    text = node.content.decode("ascii", "strict") if node.content.isascii() else ""
    if not text.endswith("Z") or len(text) < 15:
        raise TimestampError("genTime must be UTC")
    whole, _, fraction = text[:-1].partition(".")
    if (
        len(whole) != 14
        or not whole.isdigit()
        or (fraction and (not fraction.isdigit() or fraction.endswith("0")))
    ):
        raise TimestampError("bad genTime")
    stamp = datetime.strptime(whole, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    micros = int((fraction + "000000")[:6]) if fraction else 0
    return stamp.replace(microsecond=micros)


def _accuracy(node: Node) -> int:
    micros = 0
    for part in node.children():
        if part.is_(der.INTEGER):
            micros += der.read_integer(part) * 1_000_000
        elif part.is_(0, CONTEXT) and not part.constructed:
            micros += der.integer_value(part.content) * 1000
        elif part.is_(1, CONTEXT) and not part.constructed:
            micros += der.integer_value(part.content)
        else:
            raise TimestampError("bad Accuracy")
    return micros


def tst_info(content: bytes) -> TstInfo:
    parts = expect(der.parse(content), der.SEQUENCE, "a TSTInfo").children()
    if len(parts) < 5 or der.read_integer(parts[0]) != 1:
        raise TimestampError("bad TSTInfo")
    imprint = expect(parts[2], der.SEQUENCE, "a MessageImprint").children()
    if len(imprint) != 2:
        raise TimestampError("bad MessageImprint")
    accuracy: int | None = None
    ordering = False
    nonce: int | None = None
    for field in parts[5:]:
        if field.is_(der.SEQUENCE) and accuracy is None and nonce is None:
            accuracy = _accuracy(field)
        elif field.is_(der.BOOLEAN) and nonce is None:
            ordering = der.read_boolean(field)
        elif field.is_(der.INTEGER) and nonce is None:
            nonce = der.read_integer(field)
        elif field.is_(0, CONTEXT) or field.is_(1, CONTEXT):
            continue
        else:
            raise TimestampError("unexpected field in TSTInfo")
    return TstInfo(
        der.read_oid(parts[1]),
        algorithm(imprint[0]),
        der.read_octets(imprint[1]),
        der.read_integer(parts[3]),
        _time(parts[4]),
        accuracy,
        ordering,
        nonce,
    )
