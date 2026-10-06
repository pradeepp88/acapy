"""X.509 helpers for wallet-held keys.

Builds certificate signing requests whose private key never leaves the wallet,
and validates that an externally issued certificate belongs to a wallet key.

Signing is driven through ``BaseWallet.sign_message``, so the same code path
serves software keys and keys held in an external signer.
"""

import asyncio
import base64
import re
from typing import List, Optional

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.x509.oid import NameOID

from .error import WalletError
from .key_type import P256, KeyType
from .util import b58_to_bytes

_CURVE_BY_KEY_TYPE = {P256: ec.SECP256R1}

# Field name -> x509 NameOID for CSR subject building.
_SUBJECT_FIELDS = {
    "country": NameOID.COUNTRY_NAME,
    "state": NameOID.STATE_OR_PROVINCE_NAME,
    "locality": NameOID.LOCALITY_NAME,
    "organization": NameOID.ORGANIZATION_NAME,
    "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
}

_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL
)


def _curve_for(key_type: KeyType) -> ec.EllipticCurve:
    cls = _CURVE_BY_KEY_TYPE.get(key_type)
    if cls is None:
        raise WalletError(
            f"unsupported key_type {key_type} (supported: {list(_CURVE_BY_KEY_TYPE)})"
        )
    return cls()


def _hash_alg_for(key_type: KeyType) -> hashes.HashAlgorithm:
    if key_type is P256:
        return hashes.SHA256()
    raise WalletError(f"no hash paired with key_type {key_type}")


def verkey_to_public_key(verkey: str, key_type: KeyType) -> ec.EllipticCurvePublicKey:
    """Rebuild an EllipticCurvePublicKey from a base58 verkey."""
    return ec.EllipticCurvePublicKey.from_encoded_point(
        _curve_for(key_type), b58_to_bytes(verkey)
    )


class WalletBackedPrivateKey(EllipticCurvePrivateKey):
    """EllipticCurvePrivateKey adapter that signs via ``wallet.sign_message``.

    Lets ``cryptography.x509`` builders drive a wallet-held key without
    exporting it. Builders call ``.sign()`` synchronously, so we bridge back to
    the async wallet via ``run_coroutine_threadsafe`` on the captured loop;
    callers must therefore run the builder off the event loop (see
    :func:`build_csr`).
    """

    def __init__(
        self,
        wallet,
        verkey: str,
        key_type: KeyType,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        """Initialize the adapter for a wallet key."""
        self._wallet = wallet
        self._verkey = verkey
        self._curve = _curve_for(key_type)
        self._loop = loop or asyncio.get_event_loop()
        self._public_key = verkey_to_public_key(verkey, key_type)

    @property
    def curve(self) -> ec.EllipticCurve:
        """Curve of the underlying key."""
        return self._curve

    @property
    def key_size(self) -> int:
        """Key size in bits."""
        return self._public_key.key_size

    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Public half of the wallet key."""
        return self._public_key

    def sign(self, data: bytes, signature_algorithm) -> bytes:
        """Sign through the wallet, converting raw r||s to a DER signature."""
        fut = asyncio.run_coroutine_threadsafe(
            self._wallet.sign_message(data, self._verkey), self._loop
        )
        raw = fut.result()
        if raw is None or len(raw) % 2:
            raise WalletError(
                "WalletBackedPrivateKey: bad signature length "
                f"({0 if raw is None else len(raw)})"
            )
        n = len(raw) // 2
        r = int.from_bytes(raw[:n], "big")
        s = int.from_bytes(raw[n:], "big")
        return utils.encode_dss_signature(r, s)

    # ABC-satisfying stubs; unused by cryptography.x509 builders.
    def exchange(self, algorithm, peer_public_key):
        """Not supported for wallet-held signing keys."""
        raise UnsupportedAlgorithm("ECDH not supported")

    def private_numbers(self):
        """Not supported; private material stays in the wallet."""
        raise UnsupportedAlgorithm("private material not accessible")

    def private_bytes(self, encoding, format, encryption_algorithm):
        """Not supported; private material stays in the wallet."""
        raise UnsupportedAlgorithm("private material not accessible")

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        """Not supported for wallet-held signing keys."""
        raise UnsupportedAlgorithm("decrypt not supported for signer keys")

    def __copy__(self) -> "WalletBackedPrivateKey":  # noqa: D105
        return self

    def __deepcopy__(self, memo) -> "WalletBackedPrivateKey":  # noqa: D105
        return self


def _build_subject(subject: dict) -> x509.Name:
    attrs = [
        x509.NameAttribute(oid, subject[field])
        for field, oid in _SUBJECT_FIELDS.items()
        if field in subject
    ]
    cn = subject.get("cn") or subject.get("common_name")
    if cn:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    if not attrs:
        raise WalletError("subject must contain at least one field")
    return x509.Name(attrs)


def _build_csr_sync(
    private_key: WalletBackedPrivateKey, subject: dict, key_type: KeyType
) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_build_subject(subject))
        .sign(private_key, _hash_alg_for(key_type))
    )
    return csr.public_bytes(serialization.Encoding.PEM)


async def build_csr(wallet, verkey: str, key_type: KeyType, subject: dict) -> bytes:
    """Return a PEM CSR for `verkey`, signed through the wallet."""
    loop = asyncio.get_running_loop()
    adapter = WalletBackedPrivateKey(wallet, verkey, key_type, loop=loop)
    return await asyncio.to_thread(_build_csr_sync, adapter, subject, key_type)


def split_pem_chain(chain_pem: str) -> List[str]:
    """Split a PEM bundle into base64 DER strings, in document order."""
    certs = [re.sub(r"\s+", "", block) for block in _PEM_CERT_RE.findall(chain_pem)]
    if not certs:
        raise WalletError("no certificates found in PEM input")
    return certs


def chain_to_x5c(chain_pem: str) -> List[str]:
    """Return the RFC 7517 section 4.7 `x5c` form of a PEM chain.

    Entries are standard base64 DER, leaf first. Each block is parsed to reject
    malformed input early rather than at verification time.
    """
    x5c = split_pem_chain(chain_pem)
    for entry in x5c:
        try:
            x509.load_der_x509_certificate(base64.b64decode(entry))
        except Exception as err:
            raise WalletError(f"invalid certificate in chain: {err}") from err
    return x5c


def assert_cert_matches_verkey(cert_pem: bytes, verkey: str, key_type: KeyType) -> None:
    """Raise WalletError unless the leaf certificate's SPKI matches `verkey`."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as err:
        raise WalletError(f"invalid certificate PEM: {err}") from err

    cert_pub = cert.public_key()
    if not isinstance(cert_pub, ec.EllipticCurvePublicKey):
        raise WalletError("certificate public key is not an EC key")

    verkey_pub = verkey_to_public_key(verkey, key_type)
    if cert_pub.public_numbers() != verkey_pub.public_numbers():
        raise WalletError(
            "certificate SubjectPublicKeyInfo does not match the key"
        )
