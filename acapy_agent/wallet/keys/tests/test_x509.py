"""Test X.509 operations on wallet-held keys."""

import datetime
from unittest import IsolatedAsyncioTestCase

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager, multikey_to_verkey
from acapy_agent.wallet.x509 import (
    assert_cert_matches_verkey,
    build_csr,
    chain_to_x5c,
    split_pem_chain,
)

SUBJECT = {
    "country": "CA",
    "organization": "Example Issuing Authority",
    "common_name": "issuer.example.com",
}

_NOT_BEFORE = datetime.datetime(2020, 1, 1)
_NOT_AFTER = datetime.datetime(2040, 1, 1)


def _sign_csr_with_test_ca(csr_pem: bytes):
    """Act as an external CA. Returns (leaf_pem, ca_pem)."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example Test Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    csr = x509.load_pem_x509_csr(csr_pem)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_name)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("issuer.example.com")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        leaf.public_bytes(serialization.Encoding.PEM),
        ca_cert.public_bytes(serialization.Encoding.PEM),
    )


class TestWalletX509(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.profile = await create_test_profile()
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        async with self.profile.session() as session:
            self.key = await MultikeyManager(session).create(alg="p256")

    async def _key_info(self, session, multikey):
        wallet = session.inject(BaseWallet)
        return wallet, await wallet.get_signing_key(verkey=multikey_to_verkey(multikey))

    async def test_csr_is_signed_by_the_wallet_key(self):
        """The CSR must carry a valid signature made by the wallet key."""
        async with self.profile.session() as session:
            wallet, key_info = await self._key_info(session, self.key["multikey"])
            csr_pem = await build_csr(wallet, key_info.verkey, key_info.key_type, SUBJECT)

        csr = x509.load_pem_x509_csr(csr_pem)
        assert csr.is_signature_valid
        common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert common_name == "issuer.example.com"

    async def test_certificate_round_trip(self):
        """A CA-signed cert for this key imports and is retrievable."""
        async with self.profile.session() as session:
            wallet, key_info = await self._key_info(session, self.key["multikey"])
            csr_pem = await build_csr(wallet, key_info.verkey, key_info.key_type, SUBJECT)
            leaf_pem, ca_pem = _sign_csr_with_test_ca(csr_pem)

            assert_cert_matches_verkey(leaf_pem, key_info.verkey, key_info.key_type)

            chain = leaf_pem.decode() + ca_pem.decode()
            updated = await MultikeyManager(session).update_metadata(
                self.key["multikey"], {"certificate_pem": chain}
            )

        assert updated["metadata"]["certificate_pem"] == chain

        async with self.profile.session() as session:
            fetched = await MultikeyManager(session).from_multikey(self.key["multikey"])
        assert fetched["metadata"]["certificate_pem"] == chain

        x5c = chain_to_x5c(chain)
        assert len(x5c) == 2
        assert "-----BEGIN" not in x5c[0]

    async def test_certificate_for_wrong_key_is_rejected(self):
        """A cert issued for a different key must not bind."""
        async with self.profile.session() as session:
            other = await MultikeyManager(session).create(alg="p256", kid="other")
            wallet, mine = await self._key_info(session, self.key["multikey"])
            _, theirs = await self._key_info(session, other["multikey"])

            their_csr = await build_csr(wallet, theirs.verkey, theirs.key_type, SUBJECT)
            their_leaf, _ = _sign_csr_with_test_ca(their_csr)

            with self.assertRaises(WalletError) as ctx:
                assert_cert_matches_verkey(their_leaf, mine.verkey, mine.key_type)
            assert "does not match the key" in str(ctx.exception)

    async def test_metadata_survives_create(self):
        """Metadata passed at creation is persisted and returned."""
        async with self.profile.session() as session:
            created = await MultikeyManager(session).create(
                alg="p256", kid="with-meta", metadata={"purpose": "issuance"}
            )
            assert created["metadata"] == {"purpose": "issuance"}

            fetched = await MultikeyManager(session).from_multikey(created["multikey"])
            assert fetched["metadata"] == {"purpose": "issuance"}

    def test_split_pem_chain_rejects_non_pem(self):
        with self.assertRaises(WalletError):
            split_pem_chain("not a pem")
