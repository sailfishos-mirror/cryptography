# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii
import copy
import os

import pytest

from cryptography.exceptions import _Reasons
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)

from ...doubles import DummyKeySerializationEncryption
from ...utils import (
    load_nist_vectors,
    load_vectors_from_file,
    raises_unsupported_algorithm,
)


@pytest.mark.supported(
    only_if=lambda backend: not backend.mlkem_supported(),
    skip_message="Requires a backend without ML-KEM-768 support",
)
def test_mlkem_unsupported(backend):
    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MLKEM768PrivateKey.from_seed_bytes(b"0" * 64)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MLKEM768PrivateKey.generate()

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MLKEM768PublicKey.from_public_bytes(b"0" * 1184)


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
class TestMLKEM768:
    def test_encapsulate_decapsulate(self, backend):
        key = MLKEM768PrivateKey.generate()
        pub = key.public_key()
        shared_secret, ciphertext = pub.encapsulate()
        decapped = key.decapsulate(ciphertext)
        assert shared_secret == decapped
        assert len(shared_secret) == 32
        assert len(ciphertext) == 1088

    def test_private_bytes_raw(self, backend):
        key = MLKEM768PrivateKey.generate()
        raw = key.private_bytes_raw()
        assert len(raw) == 64
        assert raw == key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @pytest.mark.parametrize(
        ("encoding", "fmt", "encryption", "passwd", "load_func"),
        [
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
                None,
                serialization.load_pem_private_key,
            ),
            (
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
                None,
                serialization.load_der_private_key,
            ),
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"password"),
                b"password",
                serialization.load_pem_private_key,
            ),
            (
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"password"),
                b"password",
                serialization.load_der_private_key,
            ),
        ],
    )
    def test_round_trip_private_serialization(
        self, encoding, fmt, encryption, passwd, load_func, backend
    ):
        key = MLKEM768PrivateKey.generate()
        serialized = key.private_bytes(encoding, fmt, encryption)
        loaded_key = load_func(serialized, passwd, backend)
        assert isinstance(loaded_key, MLKEM768PrivateKey)
        # Verify round-trip by checking seed matches
        assert loaded_key.private_bytes_raw() == key.private_bytes_raw()

    @pytest.mark.parametrize(
        ("encoding", "fmt", "load_func"),
        [
            (
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
                serialization.load_pem_public_key,
            ),
            (
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
                serialization.load_der_public_key,
            ),
        ],
    )
    def test_round_trip_public_serialization(
        self, encoding, fmt, load_func, backend
    ):
        key = MLKEM768PrivateKey.generate()
        pub = key.public_key()
        serialized = pub.public_bytes(encoding, fmt)
        loaded_pub = load_func(serialized, backend)
        assert isinstance(loaded_pub, MLKEM768PublicKey)
        assert loaded_pub == pub

    def test_invalid_seed_length(self, backend):
        with pytest.raises(ValueError):
            MLKEM768PrivateKey.from_seed_bytes(b"a" * 10)

    def test_invalid_type_seed(self, backend):
        with pytest.raises(TypeError):
            MLKEM768PrivateKey.from_seed_bytes(
                object()  # type: ignore[arg-type]
            )

    def test_kat_serialization(self, backend):
        vectors = load_vectors_from_file(
            os.path.join("asymmetric", "MLKEM", "kat_MLKEM_768.rsp"),
            load_nist_vectors,
        )

        first_vector = next(iter(vectors))
        d = binascii.unhexlify(first_vector["d"])
        z = binascii.unhexlify(first_vector["z"])
        key = MLKEM768PrivateKey.from_seed_bytes(d + z)

        serialized_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        kat_pem = load_vectors_from_file(
            os.path.join("asymmetric", "MLKEM", "mlkem768.pem"),
            lambda f: f.read(),
            mode="rb",
        )
        assert serialized_pem == kat_pem

        serialized_der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        kat_der = load_vectors_from_file(
            os.path.join("asymmetric", "MLKEM", "mlkem768.der"),
            lambda f: f.read(),
            mode="rb",
        )
        assert serialized_der == kat_der

    def test_kat_vectors(self, subtests, backend):
        vectors = load_vectors_from_file(
            os.path.join("asymmetric", "MLKEM", "kat_MLKEM_768.rsp"),
            load_nist_vectors,
        )
        for vector in vectors:
            with subtests.test():
                d = binascii.unhexlify(vector["d"])
                z = binascii.unhexlify(vector["z"])

                seed = d + z
                key = MLKEM768PrivateKey.from_seed_bytes(seed)
                assert key.private_bytes_raw() == seed

                # Verify public key matches
                pub = key.public_key()
                assert pub.public_bytes_raw() == binascii.unhexlify(
                    vector["pk"]
                )

                # Verify decapsulation produces the expected shared secret
                ss = key.decapsulate(binascii.unhexlify(vector["ct"]))
                assert ss == binascii.unhexlify(vector["ss"])

                # Decapsulating an invalid ciphertext should use
                # implicit rejection, producing a deterministic but
                # different shared secret.
                ss_n = key.decapsulate(binascii.unhexlify(vector["ct_n"]))
                assert ss_n == binascii.unhexlify(vector["ss_n"])

    @pytest.mark.parametrize(
        ("encoding", "fmt", "encryption", "err"),
        [
            (
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                DummyKeySerializationEncryption(),
                ValueError,
            ),
            (
                serialization.Encoding.Raw,
                serialization.PrivateFormat.PKCS8,
                DummyKeySerializationEncryption(),
                ValueError,
            ),
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
                ValueError,
            ),
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
                ValueError,
            ),
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                DummyKeySerializationEncryption(),
                ValueError,
            ),
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"a" * 1024),
                ValueError,
            ),
            (
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                None,
                TypeError,
            ),
        ],
    )
    def test_invalid_private_bytes(
        self, encoding, fmt, encryption, err, backend
    ):
        key = MLKEM768PrivateKey.generate()
        with pytest.raises(err):
            key.private_bytes(encoding, fmt, encryption)

    def test_invalid_public_bytes(self, backend):
        key = MLKEM768PrivateKey.generate().public_key()
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.PKCS1,
            )
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.Raw,
            )


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_public_key_equality(backend):
    key = MLKEM768PrivateKey.generate()
    pub1 = key.public_key()
    pub2 = key.public_key()
    pub3 = MLKEM768PrivateKey.generate().public_key()
    assert pub1 == pub2
    assert pub1 != pub3
    assert pub1 != object()

    with pytest.raises(TypeError):
        pub1 < pub2  # type: ignore[operator]


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_public_key_copy(backend):
    key = MLKEM768PrivateKey.generate()
    pub1 = key.public_key()
    pub2 = copy.copy(pub1)
    assert pub1 == pub2


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_public_key_deepcopy(backend):
    key = MLKEM768PrivateKey.generate()
    pub1 = key.public_key()
    pub2 = copy.deepcopy(pub1)
    assert pub1 == pub2


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_private_key_copy(backend):
    key1 = MLKEM768PrivateKey.generate()
    key2 = copy.copy(key1)
    assert key1.private_bytes_raw() == key2.private_bytes_raw()


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_private_key_deepcopy(backend):
    key1 = MLKEM768PrivateKey.generate()
    key2 = copy.deepcopy(key1)
    assert key1.private_bytes_raw() == key2.private_bytes_raw()
