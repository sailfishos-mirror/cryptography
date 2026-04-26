# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import os
from functools import lru_cache
from ipaddress import IPv4Address
from typing import Optional

import pytest

from cryptography import x509
from cryptography.hazmat._oid import ExtendedKeyUsageOID
from cryptography.x509 import ExtensionType
from cryptography.x509.general_name import DNSName, IPAddress
from cryptography.x509.verification import (
    Criticality,
    ExtensionPolicy,
    Policy,
    PolicyBuilder,
    PublicKeyAlgorithm,
    SignatureAlgorithm,
    Store,
    VerificationError,
)
from tests.x509.test_x509 import _load_cert

WEBPKI_MINIMUM_RSA_MODULUS = 2048


@lru_cache(maxsize=1)
def dummy_store() -> Store:
    cert = _load_cert(
        os.path.join("x509", "cryptography.io.pem"),
        x509.load_pem_x509_certificate,
    )
    return Store([cert])


class TestPolicyBuilder:
    def test_time_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().time(datetime.datetime.now()).time(
                datetime.datetime.now()
            )

    def test_store_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().store(dummy_store()).store(dummy_store())

    def test_max_chain_depth_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().max_chain_depth(8).max_chain_depth(9)

    def test_permitted_public_key_algorithms_already_set(self):
        with pytest.raises(
            ValueError,
            match="permitted public key algorithms may only be set once",
        ):
            PolicyBuilder().permitted_public_key_algorithms(
                {PublicKeyAlgorithm.RSA}
            ).permitted_public_key_algorithms({PublicKeyAlgorithm.ED25519})

    def test_permitted_signature_algorithms_already_set(self):
        with pytest.raises(
            ValueError,
            match="permitted signature algorithms may only be set once",
        ):
            PolicyBuilder().permitted_signature_algorithms(
                {SignatureAlgorithm.RSA_PKCS1V15_SHA256}
            ).permitted_signature_algorithms({SignatureAlgorithm.ED25519})

    def test_permitted_public_key_algorithms_empty(self):
        with pytest.raises(
            ValueError,
            match="permitted_public_key_algorithms must not be empty",
        ):
            PolicyBuilder().permitted_public_key_algorithms(set())

    def test_permitted_signature_algorithms_empty(self):
        with pytest.raises(
            ValueError,
            match="permitted_signature_algorithms must not be empty",
        ):
            PolicyBuilder().permitted_signature_algorithms(set())

    def test_permitted_algorithms_default(self):
        # The default WebPKI policy includes RSA, secp256r1, secp384r1,
        # and secp521r1 SPKIs.
        verifier = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(DNSName("cryptography.io"))
        )

        assert verifier.policy.permitted_public_key_algorithms == frozenset(
            {
                PublicKeyAlgorithm.RSA,
                PublicKeyAlgorithm.SECP256R1,
                PublicKeyAlgorithm.SECP384R1,
                PublicKeyAlgorithm.SECP521R1,
            }
        )
        assert verifier.policy.permitted_signature_algorithms == frozenset(
            {
                SignatureAlgorithm.RSA_PKCS1V15_SHA256,
                SignatureAlgorithm.RSA_PKCS1V15_SHA384,
                SignatureAlgorithm.RSA_PKCS1V15_SHA512,
                SignatureAlgorithm.RSA_PSS_SHA256,
                SignatureAlgorithm.RSA_PSS_SHA384,
                SignatureAlgorithm.RSA_PSS_SHA512,
                SignatureAlgorithm.ECDSA_SHA256,
                SignatureAlgorithm.ECDSA_SHA384,
                SignatureAlgorithm.ECDSA_SHA512,
            }
        )

    def test_permitted_algorithms_custom(self):
        public_keys = {
            PublicKeyAlgorithm.RSA,
            PublicKeyAlgorithm.ED25519,
        }
        signatures = {
            SignatureAlgorithm.RSA_PKCS1V15_SHA256,
            SignatureAlgorithm.ED25519,
        }
        verifier = (
            PolicyBuilder()
            .store(dummy_store())
            .permitted_public_key_algorithms(public_keys)
            .permitted_signature_algorithms(signatures)
            .build_server_verifier(DNSName("cryptography.io"))
        )

        assert verifier.policy.permitted_public_key_algorithms == frozenset(
            public_keys
        )
        assert verifier.policy.permitted_signature_algorithms == frozenset(
            signatures
        )

    def test_ipaddress_subject(self):
        verifier = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(IPAddress(IPv4Address("0.0.0.0")))
        )
        assert verifier.policy.subject == IPAddress(IPv4Address("0.0.0.0"))

    def test_dnsname_subject(self):
        verifier = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(DNSName("cryptography.io"))
        )
        assert verifier.policy.subject == DNSName("cryptography.io")

    def test_subject_bad_types(self):
        # Subject must be a supported GeneralName type
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(
                "cryptography.io"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(
                "0.0.0.0"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(
                IPv4Address("0.0.0.0")  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(None)  # type: ignore[arg-type]

    def test_builder_pattern(self):
        now = datetime.datetime.now().replace(microsecond=0)
        store = dummy_store()
        max_chain_depth = 16

        builder = PolicyBuilder()
        builder = builder.time(now)
        builder = builder.store(store)
        builder = builder.max_chain_depth(max_chain_depth)

        subject = DNSName("cryptography.io")
        verifier = builder.build_server_verifier(subject)
        assert verifier.policy.subject == subject
        assert verifier.policy.validation_time == now
        assert verifier.policy.max_chain_depth == max_chain_depth

        assert (
            verifier.policy.extended_key_usage
            == ExtendedKeyUsageOID.SERVER_AUTH
        )
        assert (
            verifier.policy.minimum_rsa_modulus == WEBPKI_MINIMUM_RSA_MODULUS
        )
        assert verifier.store == store

    def test_build_server_verifier_missing_store(self):
        with pytest.raises(
            ValueError, match="A server verifier must have a trust store"
        ):
            PolicyBuilder().build_server_verifier(DNSName("cryptography.io"))


class TestStore:
    def test_store_rejects_empty_list(self):
        with pytest.raises(ValueError):
            Store([])

    def test_store_rejects_non_certificates(self):
        with pytest.raises(TypeError):
            Store(["not a cert"])  # type: ignore[list-item]


def _build_ed25519_chain():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    ca_key = ed25519.Ed25519PrivateKey.generate()
    leaf_key = ed25519.Ed25519PrivateKey.generate()

    ca_name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "CA")]
    )
    leaf_name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "leaf")]
    )

    not_before = datetime.datetime(2024, 1, 1)
    not_after = datetime.datetime(2034, 1, 1)
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), True
        )
        .add_extension(ca_ski, False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
        .sign(ca_key, None)
    )

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), True
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_ski
            ),
            False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
        )
        .sign(ca_key, None)
    )

    return ca_cert, leaf_cert


class TestPermittedAlgorithms:
    def test_default_policy_rejects_ed25519(self):
        ca_cert, leaf_cert = _build_ed25519_chain()
        store = Store([ca_cert])
        validation_time = datetime.datetime(2024, 6, 1)
        verifier = (
            PolicyBuilder()
            .store(store)
            .time(validation_time)
            .build_server_verifier(DNSName("example.com"))
        )

        with pytest.raises(
            VerificationError, match="Forbidden public key algorithm"
        ):
            verifier.verify(leaf_cert, [])

    def test_permitting_ed25519_allows_verification(self):
        ca_cert, leaf_cert = _build_ed25519_chain()
        store = Store([ca_cert])
        validation_time = datetime.datetime(2024, 6, 1)
        verifier = (
            PolicyBuilder()
            .store(store)
            .time(validation_time)
            .permitted_public_key_algorithms(
                {PublicKeyAlgorithm.ED25519}
            )
            .permitted_signature_algorithms(
                {SignatureAlgorithm.ED25519}
            )
            .build_server_verifier(DNSName("example.com"))
        )

        chain = verifier.verify(leaf_cert, [])
        assert chain[0] == leaf_cert
        assert chain[-1] == ca_cert

    def test_forbidding_signature_algorithm_rejects(self):
        ca_cert, leaf_cert = _build_ed25519_chain()
        store = Store([ca_cert])
        validation_time = datetime.datetime(2024, 6, 1)
        # Permit Ed25519 SPKI but not Ed25519 signatures.
        verifier = (
            PolicyBuilder()
            .store(store)
            .time(validation_time)
            .permitted_public_key_algorithms(
                {PublicKeyAlgorithm.ED25519}
            )
            .build_server_verifier(DNSName("example.com"))
        )

        with pytest.raises(
            VerificationError, match="Forbidden signature algorithm"
        ):
            verifier.verify(leaf_cert, [])


class TestClientVerifier:
    def test_build_client_verifier_missing_store(self):
        with pytest.raises(
            ValueError, match="A client verifier must have a trust store"
        ):
            PolicyBuilder().build_client_verifier()

    def test_verify(self):
        # expires 2018-11-16 01:15:03 UTC
        leaf = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        validation_time = datetime.datetime.fromisoformat(
            "2018-11-16T00:00:00+00:00"
        )
        max_chain_depth = 16

        builder = PolicyBuilder().store(store)
        builder = builder.time(validation_time).max_chain_depth(
            max_chain_depth
        )
        verifier = builder.build_client_verifier()

        assert verifier.policy.subject is None
        assert verifier.policy.validation_time == validation_time.replace(
            tzinfo=None
        )
        assert verifier.policy.max_chain_depth == max_chain_depth

        assert (
            verifier.policy.extended_key_usage
            == ExtendedKeyUsageOID.CLIENT_AUTH
        )
        assert (
            verifier.policy.minimum_rsa_modulus == WEBPKI_MINIMUM_RSA_MODULUS
        )
        assert verifier.store is store

        verified_client = verifier.verify(leaf, [])
        assert verified_client.chain == [leaf]

        assert verified_client.subjects is not None
        assert x509.DNSName("www.cryptography.io") in verified_client.subjects
        assert x509.DNSName("cryptography.io") in verified_client.subjects
        assert len(verified_client.subjects) == 2

    def test_verify_fails_renders_oid(self):
        leaf = _load_cert(
            os.path.join("x509", "custom", "ekucrit-testuser-cert.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        validation_time = datetime.datetime.fromisoformat(
            "2024-06-26T00:00:00+00:00"
        )

        builder = PolicyBuilder().store(store)
        builder = builder.time(validation_time)
        verifier = builder.build_client_verifier()

        pattern = (
            r"invalid extension: 2\.5\.29\.37: "
            r"Certificate extension has incorrect criticality"
        )
        with pytest.raises(
            VerificationError,
            match=pattern,
        ):
            verifier.verify(leaf, [])


class TestServerVerifier:
    @pytest.mark.parametrize(
        ("validation_time", "valid"),
        [
            # 03:15:02 UTC+2, or 1 second before expiry in UTC
            ("2018-11-16T03:15:02+02:00", True),
            # 00:15:04 UTC-1, or 1 second after expiry in UTC
            ("2018-11-16T00:15:04-01:00", False),
        ],
    )
    def test_verify_tz_aware(self, validation_time, valid):
        # expires 2018-11-16 01:15:03 UTC
        leaf = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        builder = PolicyBuilder().store(store)
        builder = builder.time(
            datetime.datetime.fromisoformat(validation_time)
        )
        verifier = builder.build_server_verifier(DNSName("cryptography.io"))

        if valid:
            assert verifier.verify(leaf, []) == [leaf]
        else:
            with pytest.raises(
                x509.verification.VerificationError,
                match="cert is not valid at validation time",
            ):
                verifier.verify(leaf, [])

    def test_error_message(self):
        # expires 2018-11-16 01:15:03 UTC
        leaf = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        builder = PolicyBuilder().store(store)
        verifier = builder.build_server_verifier(DNSName("cryptography.io"))

        with pytest.raises(
            x509.verification.VerificationError,
            match=r"<Certificate\(subject=.*?CN=www.cryptography.io.*?\)>",
        ):
            verifier.verify(leaf, [])


SUPPORTED_EXTENSION_TYPES = (
    x509.AuthorityInformationAccess,
    x509.AuthorityKeyIdentifier,
    x509.SubjectKeyIdentifier,
    x509.KeyUsage,
    x509.SubjectAlternativeName,
    x509.BasicConstraints,
    x509.NameConstraints,
    x509.ExtendedKeyUsage,
)


class TestCustomExtensionPolicies:
    leaf = _load_cert(
        os.path.join("x509", "cryptography.io.pem"),
        x509.load_pem_x509_certificate,
    )
    ca = _load_cert(
        os.path.join("x509", "rapidssl_sha256_ca_g3.pem"),
        x509.load_pem_x509_certificate,
    )
    store = Store([ca])
    validation_time = datetime.datetime.fromisoformat(
        "2018-11-16T00:00:00+00:00"
    )

    def test_builder_methods(self):
        ext_policy = ExtensionPolicy.permit_all()
        ext_policy = ext_policy.require_not_present(x509.BasicConstraints)

        def ensure_duplicate_ext_throws(method, *args):
            oid_str = x509.BasicConstraints.oid.dotted_string
            with pytest.raises(
                ValueError,
                match="ExtensionPolicy already configured for"
                f" extension with OID {oid_str}",
            ):
                method(ext_policy, x509.BasicConstraints, *args)

        ensure_duplicate_ext_throws(ExtensionPolicy.require_not_present)
        ensure_duplicate_ext_throws(
            ExtensionPolicy.may_be_present, Criticality.AGNOSTIC, None
        )
        ensure_duplicate_ext_throws(
            ExtensionPolicy.require_present, Criticality.AGNOSTIC, None
        )

        with pytest.raises(TypeError):

            class _Extension:
                pass

            ext_policy.require_present(
                _Extension,  # type: ignore[type-var]
                Criticality.AGNOSTIC,
                None,
            )

    def test_unsupported_extension(self):
        ext_policy = ExtensionPolicy.permit_all()
        pattern = (
            f"Unsupported extension OID: {x509.Admissions.oid.dotted_string}"
        )
        with pytest.raises(
            ValueError,
            match=pattern,
        ):
            ext_policy.may_be_present(
                x509.Admissions,
                Criticality.AGNOSTIC,
                None,
            )

    @staticmethod
    def _make_validator_cb(extension_type: type[ExtensionType]):
        def validator_cb(policy, cert, ext: Optional[ExtensionType]):
            assert isinstance(policy, Policy)
            assert (
                policy.validation_time
                == TestCustomExtensionPolicies.validation_time.replace(
                    tzinfo=None
                )
            )
            assert isinstance(cert, x509.Certificate)
            assert ext is None or isinstance(ext, extension_type)

        return validator_cb

    def test_require_not_present(self):
        default_ee = ExtensionPolicy.webpki_defaults_ee()
        no_basic_constraints_ee = default_ee.require_not_present(
            x509.BasicConstraints
        )

        default_builder = (
            PolicyBuilder().store(self.store).time(self.validation_time)
        )
        builder_no_basic_constraints = default_builder.extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=no_basic_constraints_ee,
        )

        default_builder.build_client_verifier().verify(self.leaf, [])

        with pytest.raises(
            VerificationError,
            match="Certificate contains prohibited extension",
        ):
            builder_no_basic_constraints.build_client_verifier().verify(
                self.leaf, []
            )

    def test_require_present(self):
        default_builder = (
            PolicyBuilder().store(self.store).time(self.validation_time)
        )
        builder_require_subject_keyid = default_builder.extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.webpki_defaults_ee().require_present(
                x509.SubjectKeyIdentifier,
                Criticality.AGNOSTIC,
                self._make_validator_cb(x509.SubjectKeyIdentifier),
            ),
        )
        builder_require_san = default_builder.extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.webpki_defaults_ee().require_present(
                x509.SubjectAlternativeName,
                Criticality.AGNOSTIC,
                self._make_validator_cb(x509.SubjectAlternativeName),
            ),
        )

        default_builder.build_client_verifier().verify(self.leaf, [])
        builder_require_san.build_client_verifier().verify(self.leaf, [])

        with pytest.raises(
            VerificationError,
            match="missing required extension",
        ):
            builder_require_subject_keyid.build_client_verifier().verify(
                self.leaf, []
            )

    def test_criticality_constraints(self):
        builder = PolicyBuilder().store(self.store).time(self.validation_time)
        noncrit_key_usage_builder = builder.extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.webpki_defaults_ee().require_present(
                x509.KeyUsage, Criticality.NON_CRITICAL, None
            ),
        )
        critical_eku_builder = builder.extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.webpki_defaults_ee().require_present(
                x509.ExtendedKeyUsage, Criticality.CRITICAL, None
            ),
        )

        def make_pattern(extension_type: type[ExtensionType]):
            return (
                f"invalid extension: {extension_type.oid.dotted_string}:"
                " Certificate extension has incorrect criticality"
            )

        builder.build_client_verifier().verify(self.leaf, [])
        with pytest.raises(
            VerificationError,
            match=make_pattern(x509.KeyUsage),
        ):
            noncrit_key_usage_builder.build_client_verifier().verify(
                self.leaf, []
            )
        with pytest.raises(
            VerificationError,
            match=make_pattern(x509.ExtendedKeyUsage),
        ):
            critical_eku_builder.build_client_verifier().verify(self.leaf, [])

    @pytest.mark.parametrize(
        "extension_type",
        SUPPORTED_EXTENSION_TYPES,
    )
    def test_custom_cb_pass(self, extension_type: type[x509.ExtensionType]):
        ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
        ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

        if extension_type is x509.SubjectAlternativeName:
            # subjectAltName must be required for server verification
            ee_ext_policy = ee_ext_policy.require_present(
                extension_type,
                Criticality.AGNOSTIC,
                self._make_validator_cb(extension_type),
            )
        else:
            ee_ext_policy = ee_ext_policy.may_be_present(
                extension_type,
                Criticality.AGNOSTIC,
                self._make_validator_cb(extension_type),
            )

        builder = PolicyBuilder().store(self.store)
        builder = builder.time(self.validation_time).max_chain_depth(16)
        builder = builder.extension_policies(
            ca_policy=ca_ext_policy, ee_policy=ee_ext_policy
        )

        builder.build_client_verifier().verify(self.leaf, [])

        path = builder.build_server_verifier(
            DNSName("cryptography.io")
        ).verify(self.leaf, [])
        assert path == [self.leaf, self.ca]

    @pytest.mark.parametrize(
        "extension_type",
        SUPPORTED_EXTENSION_TYPES,
    )
    def test_custom_cb_exception_fails_verification(self, extension_type):
        ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
        ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

        def validator(*_):
            raise ValueError("test")

        if extension_type is x509.BasicConstraints:
            # basicConstraints must be required in a ca extension policy
            ca_ext_policy = ca_ext_policy.require_present(
                extension_type,
                Criticality.AGNOSTIC,
                validator,
            )
        else:
            ca_ext_policy = ca_ext_policy.may_be_present(
                extension_type,
                Criticality.AGNOSTIC,
                validator,
            )

        builder = PolicyBuilder().store(self.store).time(self.validation_time)
        builder = builder.extension_policies(
            ca_policy=ca_ext_policy, ee_policy=ee_ext_policy
        )

        for verifier in (
            builder.build_client_verifier(),
            builder.build_server_verifier(DNSName("cryptography.io")),
        ):
            with pytest.raises(
                VerificationError,
                match="Python extension validator failed: ValueError: test",
            ):
                verifier.verify(self.leaf, [])

    def test_custom_cb_no_retval_enforced(self):
        ca_ext_policy = ExtensionPolicy.webpki_defaults_ca()
        ee_ext_policy = ExtensionPolicy.webpki_defaults_ee()

        def validator(*_):
            return False

        ee_ext_policy = ee_ext_policy.may_be_present(
            x509.ExtendedKeyUsage,
            Criticality.AGNOSTIC,
            validator,
        )

        builder = PolicyBuilder().store(self.store).time(self.validation_time)
        builder = builder.extension_policies(
            ca_policy=ca_ext_policy, ee_policy=ee_ext_policy
        )

        for verifier in (
            builder.build_client_verifier(),
            builder.build_server_verifier(DNSName("cryptography.io")),
        ):
            with pytest.raises(
                VerificationError,
                match=r"Python validator must return None\.",
            ):
                verifier.verify(self.leaf, [])

    def test_no_subject_alt_name(self):
        leaf = _load_cert(
            os.path.join("x509", "custom", "no_sans.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])
        validation_time = datetime.datetime.fromisoformat(
            "2025-04-14T00:00:00+00:00"
        )

        builder = PolicyBuilder().store(store)
        builder = builder.time(validation_time)

        with pytest.raises(
            VerificationError,
            match="missing required extension",
        ):
            builder.build_client_verifier().verify(leaf, [])
        with pytest.raises(
            VerificationError,
            match="missing required extension",
        ):
            builder.build_server_verifier(DNSName("example.com")).verify(
                leaf, []
            )

        builder = builder.extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.permit_all(),
        )

        verified_client = builder.build_client_verifier().verify(leaf, [])
        assert verified_client.subjects is None

        # Trying to build a ServerVerifier with an EE ExtensionPolicy
        # that doesn't require SAN extension must fail.
        with pytest.raises(
            ValueError,
            match=(
                r"An EE extension policy used for server verification"
                r" must require the subjectAltName extension to be present\."
            ),
        ):
            builder.build_server_verifier(DNSName("example.com"))

    def test_ca_ext_policy_must_require_basic_constraints(self):
        ca_policies = [
            ExtensionPolicy.webpki_defaults_ca().require_not_present(
                x509.BasicConstraints
            ),
            ExtensionPolicy.webpki_defaults_ca().may_be_present(
                x509.BasicConstraints, Criticality.AGNOSTIC, None
            ),
        ]

        for ca_policy in ca_policies:
            builder = (
                PolicyBuilder().store(self.store).time(self.validation_time)
            )
            builder = builder.extension_policies(
                ca_policy=ca_policy,
                ee_policy=ExtensionPolicy.webpki_defaults_ee(),
            )
            pattern = (
                "A CA extension policy must require the"
                " basicConstraints extension to be present."
            )
            with pytest.raises(
                ValueError,
                match=pattern,
            ):
                builder.build_server_verifier(DNSName("example.com"))
            with pytest.raises(
                ValueError,
                match=pattern,
            ):
                builder.build_client_verifier()

    def test_wrong_subject_alt_name(self):
        ee_extension_policy = (
            ExtensionPolicy.webpki_defaults_ee().require_present(
                x509.SubjectAlternativeName, Criticality.AGNOSTIC, None
            )
        )
        builder = PolicyBuilder().store(self.store)
        builder = builder.time(self.validation_time)
        builder = builder.extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ee_extension_policy,
        )

        builder.build_client_verifier().verify(self.leaf, [])

        # For ServerVerifier, SAN must be matched against the subject
        # even if the extension policy permits any SANs.
        with pytest.raises(
            VerificationError,
            match="leaf certificate has no matching subjectAltName",
        ):
            builder.build_server_verifier(DNSName("wrong.io")).verify(
                self.leaf, []
            )
