from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from . import der, tsp
from .errors import TimestampError

HASHES = {
    "sha256": ("2.16.840.1.101.3.4.2.1", hashes.SHA256, 32),
    "sha384": ("2.16.840.1.101.3.4.2.2", hashes.SHA384, 48),
    "sha512": ("2.16.840.1.101.3.4.2.3", hashes.SHA512, 64),
}
BY_OID = {oid: (name, cls) for name, (oid, cls, _) in HASHES.items()}
BY_OID["1.3.14.3.2.26"] = ("sha1", hashes.SHA1)
RSA_WITH = {
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}
ECDSA_WITH = {
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
MAX_CHAIN = 8
NAME_VALUE_TYPES = {3, 12, 16, 18, 19, 20, 22, 28, 30}
FAULTS = (
    ValueError,
    TypeError,
    IndexError,
    KeyError,
    OverflowError,
    UnicodeError,
    InvalidSignature,
    UnsupportedAlgorithm,
    x509.InvalidVersion,
    x509.DuplicateExtension,
    x509.UnsupportedGeneralNameType,
)


@dataclass(frozen=True, slots=True)
class TokenInfo:
    gen_time: datetime
    serial: int
    policy: str
    hash_algorithm: str
    digest: bytes
    nonce: int | None
    accuracy_micros: int | None
    signer: x509.Certificate


def _params(alg: tsp.Algorithm, *, null_ok: bool) -> None:
    params = alg.parameters
    if params is None:
        return
    if null_ok and params.is_(der.NULL) and not params.constructed and not params.content:
        return
    raise TimestampError(f"unexpected parameters for algorithm {alg.oid}")


def build_request(
    digest: bytes, hash_alg: str = "sha256", nonce: int | None = None, cert_req: bool = True
) -> bytes:
    if hash_alg not in HASHES or len(digest) != HASHES[hash_alg][2]:
        raise TimestampError("digest does not match the hash algorithm")
    fields = [
        der.integer(1),
        der.sequence(
            der.sequence(der.oid(HASHES[hash_alg][0]), der.null()), der.octet_string(digest)
        ),
    ]
    if nonce is not None:
        fields.append(der.integer(nonce))
    if cert_req:
        fields.append(der.boolean(True))
    return der.sequence(*fields)


def new_nonce() -> int:
    return secrets.randbits(63)


def parse_response(data: bytes) -> bytes:
    try:
        status, token = tsp.response_status(data)
    except FAULTS as exc:
        raise TimestampError(f"unreadable response: {type(exc).__name__}") from None
    if status not in (0, 1) or token is None:
        raise TimestampError(f"timestamp not granted (status {status})")
    return token


def _hash(name: str, data: bytes) -> bytes:
    if name == "sha1":
        return hashlib.sha1(data, usedforsecurity=False).digest()
    return hashlib.new(name, data).digest()


def _issuer_bytes(cert: x509.Certificate) -> bytes:
    fields = der.parse(cert.tbs_certificate_bytes).children()
    offset = 1 if fields[0].is_(0, der.CONTEXT) else 0
    return fields[offset + 2].raw


def _signer_certificate(signed: tsp.SignedData) -> tuple[x509.Certificate, list[x509.Certificate]]:
    certs = [x509.load_der_x509_certificate(raw) for raw in signed.certificates]
    info = signed.signer
    for cert in certs:
        if info.key_id is not None:
            try:
                ski = cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value.digest
            except x509.ExtensionNotFound:
                continue
            if ski == info.key_id:
                return cert, certs
        elif cert.serial_number == info.serial and info.issuer == _issuer_bytes(cert):
            return cert, certs
    raise TimestampError("the signer certificate is not in the token")


def _check_ess(attrs: dict[str, list[der.Node]], signer: x509.Certificate) -> None:
    body = signer.public_bytes(Encoding.DER)
    for name, default in (
        (tsp.SIGNING_CERTIFICATE_V2, "sha256"),
        (tsp.SIGNING_CERTIFICATE, "sha1"),
    ):
        if name not in attrs:
            continue
        values = attrs[name]
        if len(values) != 1:
            raise TimestampError("bad signing certificate attribute")
        certs = tsp.expect(values[0].children()[0], der.SEQUENCE, "ESS certificate ids").children()
        first = certs[0].children()
        algo = default
        if first[0].is_(der.SEQUENCE):
            ess_alg = tsp.algorithm(first[0])
            _params(ess_alg, null_ok=True)
            algo = BY_OID.get(ess_alg.oid, ("", None))[0]
            first = first[1:]
        if not algo or der.read_octets(first[0]) != _hash(algo, body):
            raise TimestampError("signing certificate attribute does not match the signer")
        return
    raise TimestampError("no signing certificate attribute")


def _verify_signature(signed: tsp.SignedData, signer: x509.Certificate) -> None:
    info = signed.signer
    received = info.signed_attrs.content
    members = [m.raw for m in der.read_all(received)]
    if b"".join(sorted(members)) != received:
        raise TimestampError("signed attributes were not DER encoded")
    canonical = der.tlv(0x31, received)
    digest_name = BY_OID.get(info.digest_algorithm.oid, ("", None))[0]
    if digest_name not in HASHES:
        raise TimestampError("unsupported digest algorithm")
    _params(info.digest_algorithm, null_ok=True)
    for listed in signed.digest_algorithms:
        if listed.oid not in BY_OID:
            raise TimestampError("SignedData lists an unknown digest algorithm")
        _params(listed, null_ok=True)
    if info.digest_algorithm.oid not in {a.oid for a in signed.digest_algorithms}:
        raise TimestampError("SignedData digest algorithms do not cover the signer")
    attrs = tsp.signed_attributes(info)
    kinds = attrs.get(tsp.CONTENT_TYPE, [])
    if len(kinds) != 1 or der.read_oid(kinds[0]) != tsp.TST_INFO:
        raise TimestampError("content-type attribute is not id-ct-TSTInfo")
    digests = attrs.get(tsp.MESSAGE_DIGEST, [])
    if len(digests) != 1 or der.read_octets(digests[0]) != _hash(digest_name, signed.content):
        raise TimestampError("message digest does not match the TSTInfo")
    _check_ess(attrs, signer)
    key = signer.public_key()
    algo = info.signature_algorithm.oid
    chosen = HASHES[digest_name][1]()
    if isinstance(key, rsa.RSAPublicKey) and (algo == RSA_ENCRYPTION or algo in RSA_WITH):
        _params(info.signature_algorithm, null_ok=True)
        if algo in RSA_WITH:
            chosen = HASHES[RSA_WITH[algo]][1]()
        key.verify(info.signature, canonical, padding.PKCS1v15(), chosen)
    elif isinstance(key, ec.EllipticCurvePublicKey) and algo in ECDSA_WITH:
        _params(info.signature_algorithm, null_ok=False)
        key.verify(info.signature, canonical, ec.ECDSA(HASHES[ECDSA_WITH[algo]][1]()))
    else:
        raise TimestampError("unsupported signature algorithm")


def _check_eku(signer: x509.Certificate) -> None:
    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        raise TimestampError("signer has no extended key usage") from None
    if not eku.critical or list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise TimestampError("signer extended key usage is not critical timeStamping only")


def _within(cert: x509.Certificate, at: datetime) -> None:
    if not cert.not_valid_before_utc <= at <= cert.not_valid_after_utc:
        raise TimestampError("a certificate in the chain was not valid at genTime")


def _strict_walk(node: der.Node, depth: int = 0) -> None:
    if node.constructed:
        for child in node.children(depth=depth):
            _strict_walk(child, depth + 1)


def _check_name(node: der.Node) -> None:
    for rdn in tsp.expect(node, der.SEQUENCE, "a Name").children():
        for pair in tsp.expect(rdn, der.SET, "an RDN").children():
            parts = tsp.expect(pair, der.SEQUENCE, "an attribute").children()
            if len(parts) != 2:
                raise TimestampError("bad Name attribute")
            der.read_oid(parts[0])
            if parts[1].cls != der.UNIVERSAL or parts[1].number not in NAME_VALUE_TYPES:
                raise TimestampError("a Name value is not a directory string")


def _check_structure(raw: bytes) -> None:
    cert = der.parse(raw)
    _strict_walk(cert)
    parts = cert.children()
    if len(parts) != 3:
        raise TimestampError("bad certificate")
    tbs = parts[0].children()
    offset = 1 if tbs[0].is_(0, der.CONTEXT) else 0
    _check_name(tbs[offset + 2])
    _check_name(tbs[offset + 4])
    if tbs[offset + 1].raw != parts[1].raw:
        raise TimestampError("certificate signature algorithms disagree")
    key_info = tsp.expect(tbs[offset + 5], der.SEQUENCE, "a SubjectPublicKeyInfo").children()
    for bits in (parts[2], key_info[-1]):
        if not bits.is_(der.BIT_STRING) or bits.content[:1] != b"\x00":
            raise TimestampError("a signature or key BIT STRING is not octet aligned")
    for field in tbs[offset + 6 :]:
        if field.is_(3, der.CONTEXT):
            for ext in field.children()[0].children():
                der.parse(der.read_octets(ext.children()[-1]))


def _check_pool(
    raws: list[bytes], pool: list[x509.Certificate], roots: Sequence[x509.Certificate]
) -> None:
    for raw, cert in zip(raws, pool, strict=True):
        _check_structure(raw)
        list(cert.extensions)
        issuers = [c for c in [*roots, *pool] if c.subject == cert.issuer]
        verified = False
        for issuer in issuers:
            try:
                cert.verify_directly_issued_by(issuer)
            except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
                continue
            verified = True
            break
        if issuers and not verified:
            raise TimestampError("a certificate in the token does not verify against its issuer")


def _chain(
    signer: x509.Certificate,
    pool: list[x509.Certificate],
    roots: Sequence[x509.Certificate],
    at: datetime,
) -> None:
    pinned = {r.public_bytes(Encoding.DER) for r in roots}
    current = signer
    for _ in range(MAX_CHAIN):
        _within(current, at)
        if current.public_bytes(Encoding.DER) in pinned:
            return
        for candidate in [*roots, *pool]:
            if candidate.subject != current.issuer or candidate == current:
                continue
            try:
                current.verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
                continue
            if candidate.public_bytes(Encoding.DER) in pinned:
                _within(candidate, at)
                return
            try:
                constraints = candidate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
            except x509.ExtensionNotFound:
                raise TimestampError("an intermediate is not a CA") from None
            if not constraints.ca:
                raise TimestampError("an intermediate is not a CA")
            current = candidate
            break
        else:
            raise TimestampError("no chain to a pinned root")
    raise TimestampError("chain too long")


def verify(
    token: bytes,
    digest: bytes,
    roots: Sequence[x509.Certificate],
    *,
    hash_alg: str = "sha256",
    nonce: int | None = None,
) -> TokenInfo:
    try:
        return _verify(token, digest, roots, hash_alg, nonce)
    except TimestampError:
        raise
    except FAULTS as exc:
        raise TimestampError(f"invalid token: {type(exc).__name__}") from None


def _verify(
    token: bytes, digest: bytes, roots: Sequence[x509.Certificate], hash_alg: str, nonce: int | None
) -> TokenInfo:
    if not roots:
        raise TimestampError("no pinned roots")
    signed = tsp.signed_data(token)
    if signed.content_type != tsp.TST_INFO:
        raise TimestampError("eContentType is not id-ct-TSTInfo")
    info = tsp.tst_info(signed.content)
    signer, pool = _signer_certificate(signed)
    _verify_signature(signed, signer)
    _check_eku(signer)
    _check_pool(signed.certificates, pool, roots)
    _chain(signer, pool, roots, info.gen_time)
    expected = HASHES.get(hash_alg)
    _params(info.hash_algorithm, null_ok=True)
    if expected is None or info.hash_algorithm.oid != expected[0] or info.hashed_message != digest:
        raise TimestampError("message imprint does not match the digest")
    if nonce is not None and info.nonce != nonce:
        raise TimestampError("nonce does not match")
    return TokenInfo(
        info.gen_time,
        info.serial,
        info.policy,
        hash_alg,
        info.hashed_message,
        info.nonce,
        info.accuracy_micros,
        signer,
    )
