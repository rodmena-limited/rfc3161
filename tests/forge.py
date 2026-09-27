from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from rodmena_rfc3161 import der

SHA256 = "2.16.840.1.101.3.4.2.1"
NOW = datetime.now(UTC).replace(microsecond=0)


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class Authority:
    eku: str = "critical"
    root_key: rsa.RSAPrivateKey = field(default_factory=_key)
    key: rsa.RSAPrivateKey = field(default_factory=_key)
    root: x509.Certificate = field(init=False)
    signer: x509.Certificate = field(init=False)

    def __post_init__(self) -> None:
        start, end = NOW - timedelta(days=1), NOW + timedelta(days=30)
        self.root = (
            x509.CertificateBuilder()
            .subject_name(_name("forge root"))
            .issuer_name(_name("forge root"))
            .public_key(self.root_key.public_key())
            .serial_number(1)
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.root_key, hashes.SHA256())
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name("forge tsa"))
            .issuer_name(_name("forge root"))
            .public_key(self.key.public_key())
            .serial_number(2)
            .not_valid_before(start)
            .not_valid_after(end)
        )
        if self.eku != "none":
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
                critical=self.eku == "critical",
            )
        self.signer = builder.sign(self.root_key, hashes.SHA256())


def _attribute(oid: str, value: bytes) -> bytes:
    return der.sequence(der.oid(oid), der.tlv(0x31, value))


def tst_info(digest: bytes, nonce: int | None, when: datetime = NOW) -> bytes:
    fields = [
        der.integer(1),
        der.oid("1.2.3.4.1"),
        der.sequence(der.sequence(der.oid(SHA256), der.null()), der.octet_string(digest)),
        der.integer(77),
        der.tlv(der.GENERALIZED_TIME, when.strftime("%Y%m%d%H%M%SZ").encode()),
    ]
    if nonce is not None:
        fields.append(der.integer(nonce))
    return der.sequence(*fields)


def token(
    authority: Authority,
    content: bytes,
    *,
    unsorted_attrs: bool = False,
    unsorted_certs: bool = True,
) -> bytes:
    cert_der = authority.signer.public_bytes(Encoding.DER)
    root_der = authority.root.public_bytes(Encoding.DER)
    ess = der.sequence(
        der.sequence(der.sequence(der.octet_string(hashlib.sha256(cert_der).digest())))
    )
    attrs = [
        _attribute("1.2.840.113549.1.9.3", der.oid("1.2.840.113549.1.9.16.1.4")),
        _attribute("1.2.840.113549.1.9.4", der.octet_string(hashlib.sha256(content).digest())),
        _attribute("1.2.840.113549.1.9.16.2.47", ess),
    ]
    ordered = sorted(attrs)
    body = b"".join(reversed(ordered) if unsorted_attrs else ordered)
    signature = authority.key.sign(der.tlv(0x31, body), padding.PKCS1v15(), hashes.SHA256())
    fields = x509.load_der_x509_certificate(cert_der).tbs_certificate_bytes
    tbs = der.parse(fields).children()
    issuer = tbs[3].raw if tbs[0].is_(0, der.CONTEXT) else tbs[2].raw
    signer_info = der.sequence(
        der.integer(1),
        der.sequence(issuer, der.integer(authority.signer.serial_number)),
        der.sequence(der.oid(SHA256), der.null()),
        der.tlv(0xA0, body),
        der.sequence(der.oid("1.2.840.113549.1.1.1"), der.null()),
        der.octet_string(signature),
    )
    certs = [cert_der, root_der]
    certs = sorted(certs, reverse=True) if unsorted_certs else sorted(certs)
    signed = der.sequence(
        der.integer(3),
        der.tlv(0x31, der.sequence(der.oid(SHA256), der.null())),
        der.sequence(
            der.oid("1.2.840.113549.1.9.16.1.4"), der.tlv(0xA0, der.octet_string(content))
        ),
        der.tlv(0xA0, b"".join(certs)),
        der.tlv(0x31, signer_info),
    )
    return der.sequence(der.oid("1.2.840.113549.1.7.2"), der.tlv(0xA0, signed))


def response(token_der: bytes, status: int = 0) -> bytes:
    return der.sequence(der.sequence(der.integer(status)), token_der)
