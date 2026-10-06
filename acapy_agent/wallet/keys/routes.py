"""Key admin routes."""

import logging

from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, request_schema, response_schema
from marshmallow import fields

from ...admin.decorators.auth import tenant_authentication
from ...admin.request_context import AdminRequestContext
from ...messaging.models.openapi import OpenAPISchema
from ...wallet.error import WalletDuplicateError, WalletError, WalletNotFoundError
from ..base import BaseWallet
from ..routes import WALLET_TAG_TITLE
from ..x509 import assert_cert_matches_verkey, build_csr, chain_to_x5c
from .manager import (
    DEFAULT_ALG,
    MultikeyManager,
    MultikeyManagerError,
    multikey_to_verkey,
)

LOGGER = logging.getLogger(__name__)

CERTIFICATE_METADATA_KEY = "certificate_pem"


class CreateKeyRequestSchema(OpenAPISchema):
    """Request schema for creating a new key."""

    alg = fields.Str(
        required=False,
        metadata={
            "description": "Which key algorithm to use.",
            "example": DEFAULT_ALG,
        },
    )

    seed = fields.Str(
        required=False,
        metadata={
            "description": (
                "Optional seed to generate the key pair. "
                "Must enable insecure wallet mode."
            ),
            "example": "00000000000000000000000000000000",
        },
    )

    kid = fields.Str(
        required=False,
        metadata={
            "description": (
                "Optional kid to bind to the keypair, such as a verificationMethod."
            ),
            "example": "did:web:example.com#key-01",
        },
    )

    metadata = fields.Dict(
        required=False,
        metadata={
            "description": "Optional metadata to bind to the keypair.",
            "example": {"purpose": "issuance"},
        },
    )


class CreateKeyResponseSchema(OpenAPISchema):
    """Response schema from creating a new key."""

    multikey = fields.Str(
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        },
    )

    kid = fields.Str(
        metadata={
            "description": "The associated kid",
            "example": "did:web:example.com#key-01",
        },
    )


class UpdateKeyRequestSchema(OpenAPISchema):
    """Request schema for updating an existing key pair."""

    multikey = fields.Str(
        required=True,
        metadata={
            "description": "Multikey of the key pair to update",
            "example": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        },
    )

    kid = fields.Str(
        required=True,
        metadata={
            "description": (
                "New kid to bind to the key pair, such as a verificationMethod."
            ),
            "example": "did:web:example.com#key-02",
        },
    )


class UpdateKeyResponseSchema(OpenAPISchema):
    """Response schema from updating an existing key pair."""

    multikey = fields.Str(
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        },
    )

    kid = fields.Str(
        metadata={
            "description": "The associated kid",
            "example": "did:web:example.com#key-02",
        },
    )


class FetchKeyResponseSchema(OpenAPISchema):
    """Response schema from updating an existing key pair."""

    multikey = fields.Str(
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        },
    )

    kid = fields.Str(
        metadata={
            "description": "The associated kid",
            "example": "did:web:example.com#key-01",
        },
    )

    metadata = fields.Dict(
        metadata={
            "description": "Metadata bound to the key, such as a certificate",
            "example": {"certificate_pem": "-----BEGIN CERTIFICATE-----\n..."},
        },
    )


class MultikeyMatchInfoSchema(OpenAPISchema):
    """Path parameters for key operations."""

    multikey = fields.Str(
        required=True,
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": "zDnaeaqzTWBtkgYZFwMCAJQwR7rDVxJmbUJtNhnDD3YG3ysTb",
        },
    )


class CreateCsrRequestSchema(OpenAPISchema):
    """Request schema for building a CSR."""

    subject = fields.Dict(
        required=True,
        metadata={
            "description": (
                "CSR subject. Recognised fields: country, state, locality, "
                "organization, organizational_unit, common_name."
            ),
            "example": {
                "country": "CA",
                "organization": "Example Issuing Authority",
                "common_name": "issuer.example.com",
            },
        },
    )


class CreateCsrResponseSchema(OpenAPISchema):
    """Response schema from building a CSR."""

    csr_pem = fields.Str(
        metadata={
            "description": "PEM-encoded certificate signing request",
            "example": "-----BEGIN CERTIFICATE REQUEST-----\n...",
        },
    )


class ImportCertificateRequestSchema(OpenAPISchema):
    """Request schema for importing a certificate chain."""

    certificate_pem = fields.Str(
        required=True,
        metadata={
            "description": (
                "PEM certificate chain, leaf first. The leaf public key must "
                "match the key it is imported onto."
            ),
            "example": "-----BEGIN CERTIFICATE-----\n...",
        },
    )


class ImportCertificateResponseSchema(OpenAPISchema):
    """Response schema from importing a certificate chain."""

    multikey = fields.Str(
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": "zDnaeaqzTWBtkgYZFwMCAJQwR7rDVxJmbUJtNhnDD3YG3ysTb",
        },
    )

    certificate_pem = fields.Str(
        metadata={"description": "The stored PEM chain"},
    )

    x5c = fields.List(
        fields.Str(),
        metadata={
            "description": (
                "The chain as base64 DER, leaf first, for use as a JOSE "
                "x5c header (RFC 7517 section 4.7)"
            )
        },
    )


@docs(tags=[WALLET_TAG_TITLE], summary="Fetch key info.")
@response_schema(FetchKeyResponseSchema, 200, description="")
@tenant_authentication
async def fetch_key(request: web.BaseRequest):
    """Request handler for fetching a key.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    multikey = request.match_info["multikey"]

    try:
        async with context.session() as session:
            key_info = await MultikeyManager(session).from_multikey(multikey=multikey)
        return web.json_response(
            key_info,
            status=200,
        )

    except (MultikeyManagerError, WalletDuplicateError, WalletNotFoundError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=[WALLET_TAG_TITLE], summary="Create a key pair")
@request_schema(CreateKeyRequestSchema())
@response_schema(CreateKeyResponseSchema, 200, description="")
@tenant_authentication
async def create_key(request: web.BaseRequest):
    """Request handler for creating a new key pair in the wallet.

    Args:
        request: aiohttp request object

    Returns:
        The Public Key Multibase format (multikey)

    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    seed = body.get("seed") or None
    kid = body.get("kid") or None
    alg = body.get("alg") or DEFAULT_ALG
    metadata = body.get("metadata") or None

    if seed and not context.settings.get("wallet.allow_insecure_seed"):
        raise MultikeyManagerError("Seed support is not enabled.")

    try:
        async with context.session() as session:
            key_info = await MultikeyManager(session).create(
                seed=seed, kid=kid, alg=alg, metadata=metadata
            )
        return web.json_response(
            key_info,
            status=201,
        )
    except (MultikeyManagerError, WalletDuplicateError, WalletNotFoundError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=[WALLET_TAG_TITLE], summary="Update a key pair's kid")
@request_schema(UpdateKeyRequestSchema())
@response_schema(UpdateKeyResponseSchema, 200, description="")
@tenant_authentication
async def update_key(request: web.BaseRequest):
    """Request handler for creating a new key pair in the wallet.

    Args:
        request: aiohttp request object

    Returns:
        The Public Key Multibase format (multikey)

    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    multikey = body.get("multikey")
    kid = body.get("kid")

    try:
        async with context.session() as session:
            key_info = await MultikeyManager(session).update(
                multikey=multikey,
                kid=kid,
            )
        return web.json_response(
            key_info,
            status=200,
        )
    except (MultikeyManagerError, WalletDuplicateError, WalletNotFoundError) as err:
        return web.json_response({"message": str(err)}, status=400)


async def _key_for_multikey(session, multikey: str):
    """Resolve a multikey to its wallet KeyInfo, or raise MultikeyManagerError."""
    wallet = session.inject(BaseWallet)
    try:
        key_info = await wallet.get_signing_key(verkey=multikey_to_verkey(multikey))
    except WalletNotFoundError as err:
        raise MultikeyManagerError(f"Unknown multikey {multikey}.") from err
    return wallet, key_info


@docs(tags=[WALLET_TAG_TITLE], summary="Create a certificate signing request")
@match_info_schema(MultikeyMatchInfoSchema())
@request_schema(CreateCsrRequestSchema())
@response_schema(CreateCsrResponseSchema, 200, description="")
@tenant_authentication
async def create_csr(request: web.BaseRequest):
    """Request handler for building a CSR for a wallet-held key.

    Args:
        request: aiohttp request object

    Returns:
        The PEM-encoded certificate signing request

    """
    context: AdminRequestContext = request["context"]
    multikey = request.match_info["multikey"]
    body = await request.json()
    subject = body.get("subject") or {}

    if not subject:
        return web.json_response({"message": "subject is required"}, status=400)

    try:
        async with context.session() as session:
            wallet, key_info = await _key_for_multikey(session, multikey)
            csr_pem = await build_csr(
                wallet, key_info.verkey, key_info.key_type, subject
            )
        return web.json_response({"csr_pem": csr_pem.decode()}, status=200)
    except (MultikeyManagerError, WalletError, WalletNotFoundError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=[WALLET_TAG_TITLE], summary="Import a certificate chain for a key")
@match_info_schema(MultikeyMatchInfoSchema())
@request_schema(ImportCertificateRequestSchema())
@response_schema(ImportCertificateResponseSchema, 200, description="")
@tenant_authentication
async def import_certificate(request: web.BaseRequest):
    """Request handler for binding an externally issued certificate to a key.

    Args:
        request: aiohttp request object

    Returns:
        The stored chain, plus its base64 DER (x5c) form

    """
    context: AdminRequestContext = request["context"]
    multikey = request.match_info["multikey"]
    body = await request.json()
    certificate_pem = body.get("certificate_pem")

    if not certificate_pem:
        return web.json_response(
            {"message": "certificate_pem is required"}, status=400
        )

    try:
        async with context.session() as session:
            _, key_info = await _key_for_multikey(session, multikey)
            # load_pem_x509_certificate reads the first block, i.e. the leaf.
            assert_cert_matches_verkey(
                certificate_pem.encode(), key_info.verkey, key_info.key_type
            )
            x5c = chain_to_x5c(certificate_pem)

            manager = MultikeyManager(session)
            updated = await manager.update_metadata(
                multikey,
                {**(key_info.metadata or {}), CERTIFICATE_METADATA_KEY: certificate_pem},
            )

        return web.json_response(
            {
                "multikey": updated["multikey"],
                "certificate_pem": certificate_pem,
                "x5c": x5c,
            },
            status=200,
        )
    except (MultikeyManagerError, WalletError, WalletNotFoundError) as err:
        return web.json_response({"message": str(err)}, status=400)


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get("/wallet/keys/{multikey}", fetch_key, allow_head=False),
            web.post("/wallet/keys", create_key),
            web.put("/wallet/keys", update_key),
            web.post("/wallet/keys/{multikey}/csr", create_csr),
            web.post("/wallet/keys/{multikey}/certificate", import_certificate),
        ]
    )
