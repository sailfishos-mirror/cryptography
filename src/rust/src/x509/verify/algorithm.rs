// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::AlgorithmIdentifier;
use cryptography_x509_verification::policy::{
    ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, ED25519, ED448, RSASSA_PKCS1V15_SHA256,
    RSASSA_PKCS1V15_SHA384, RSASSA_PKCS1V15_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384,
    RSASSA_PSS_SHA512, SPKI_ED25519, SPKI_ED448, SPKI_RSA, SPKI_SECP256R1, SPKI_SECP384R1,
    SPKI_SECP521R1,
};

/// Public key algorithms that may be used in an X.509 verification
/// policy. Mirrors the SubjectPublicKeyInfo AlgorithmIdentifiers from
/// CA/B Forum 7.1.3.1, with Ed25519/Ed448 added.
#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.x509.verification",
    name = "PublicKeyAlgorithm"
)]
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub(crate) enum PyPublicKeyAlgorithm {
    #[pyo3(name = "RSA")]
    Rsa,
    #[pyo3(name = "SECP256R1")]
    Secp256R1,
    #[pyo3(name = "SECP384R1")]
    Secp384R1,
    #[pyo3(name = "SECP521R1")]
    Secp521R1,
    #[pyo3(name = "ED25519")]
    Ed25519,
    #[pyo3(name = "ED448")]
    Ed448,
}

impl PyPublicKeyAlgorithm {
    pub(crate) fn as_algorithm_identifier(&self) -> AlgorithmIdentifier<'static> {
        match self {
            PyPublicKeyAlgorithm::Rsa => SPKI_RSA.clone(),
            PyPublicKeyAlgorithm::Secp256R1 => SPKI_SECP256R1.clone(),
            PyPublicKeyAlgorithm::Secp384R1 => SPKI_SECP384R1.clone(),
            PyPublicKeyAlgorithm::Secp521R1 => SPKI_SECP521R1.clone(),
            PyPublicKeyAlgorithm::Ed25519 => SPKI_ED25519.clone(),
            PyPublicKeyAlgorithm::Ed448 => SPKI_ED448.clone(),
        }
    }

    pub(crate) fn from_algorithm_identifier(alg: &AlgorithmIdentifier<'_>) -> Option<Self> {
        if alg == &SPKI_RSA {
            Some(PyPublicKeyAlgorithm::Rsa)
        } else if alg == &SPKI_SECP256R1 {
            Some(PyPublicKeyAlgorithm::Secp256R1)
        } else if alg == &SPKI_SECP384R1 {
            Some(PyPublicKeyAlgorithm::Secp384R1)
        } else if alg == &SPKI_SECP521R1 {
            Some(PyPublicKeyAlgorithm::Secp521R1)
        } else if alg == &SPKI_ED25519 {
            Some(PyPublicKeyAlgorithm::Ed25519)
        } else if alg == &SPKI_ED448 {
            Some(PyPublicKeyAlgorithm::Ed448)
        } else {
            None
        }
    }
}

/// Signature algorithms that may be used in an X.509 verification
/// policy. Mirrors the signature AlgorithmIdentifiers from CA/B Forum
/// 7.1.3.2, with Ed25519/Ed448 added.
#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.x509.verification",
    name = "SignatureAlgorithm"
)]
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub(crate) enum PySignatureAlgorithm {
    #[pyo3(name = "RSA_PKCS1V15_SHA256")]
    RsaPkcs1V15Sha256,
    #[pyo3(name = "RSA_PKCS1V15_SHA384")]
    RsaPkcs1V15Sha384,
    #[pyo3(name = "RSA_PKCS1V15_SHA512")]
    RsaPkcs1V15Sha512,
    #[pyo3(name = "RSA_PSS_SHA256")]
    RsaPssSha256,
    #[pyo3(name = "RSA_PSS_SHA384")]
    RsaPssSha384,
    #[pyo3(name = "RSA_PSS_SHA512")]
    RsaPssSha512,
    #[pyo3(name = "ECDSA_SHA256")]
    EcdsaSha256,
    #[pyo3(name = "ECDSA_SHA384")]
    EcdsaSha384,
    #[pyo3(name = "ECDSA_SHA512")]
    EcdsaSha512,
    #[pyo3(name = "ED25519")]
    Ed25519,
    #[pyo3(name = "ED448")]
    Ed448,
}

impl PySignatureAlgorithm {
    pub(crate) fn as_algorithm_identifier(&self) -> AlgorithmIdentifier<'static> {
        match self {
            PySignatureAlgorithm::RsaPkcs1V15Sha256 => RSASSA_PKCS1V15_SHA256.clone(),
            PySignatureAlgorithm::RsaPkcs1V15Sha384 => RSASSA_PKCS1V15_SHA384.clone(),
            PySignatureAlgorithm::RsaPkcs1V15Sha512 => RSASSA_PKCS1V15_SHA512.clone(),
            PySignatureAlgorithm::RsaPssSha256 => RSASSA_PSS_SHA256.clone(),
            PySignatureAlgorithm::RsaPssSha384 => RSASSA_PSS_SHA384.clone(),
            PySignatureAlgorithm::RsaPssSha512 => RSASSA_PSS_SHA512.clone(),
            PySignatureAlgorithm::EcdsaSha256 => ECDSA_SHA256.clone(),
            PySignatureAlgorithm::EcdsaSha384 => ECDSA_SHA384.clone(),
            PySignatureAlgorithm::EcdsaSha512 => ECDSA_SHA512.clone(),
            PySignatureAlgorithm::Ed25519 => ED25519.clone(),
            PySignatureAlgorithm::Ed448 => ED448.clone(),
        }
    }

    pub(crate) fn from_algorithm_identifier(alg: &AlgorithmIdentifier<'_>) -> Option<Self> {
        if alg == &RSASSA_PKCS1V15_SHA256 {
            Some(PySignatureAlgorithm::RsaPkcs1V15Sha256)
        } else if alg == &RSASSA_PKCS1V15_SHA384 {
            Some(PySignatureAlgorithm::RsaPkcs1V15Sha384)
        } else if alg == &RSASSA_PKCS1V15_SHA512 {
            Some(PySignatureAlgorithm::RsaPkcs1V15Sha512)
        } else if alg == &*RSASSA_PSS_SHA256 {
            Some(PySignatureAlgorithm::RsaPssSha256)
        } else if alg == &*RSASSA_PSS_SHA384 {
            Some(PySignatureAlgorithm::RsaPssSha384)
        } else if alg == &*RSASSA_PSS_SHA512 {
            Some(PySignatureAlgorithm::RsaPssSha512)
        } else if alg == &ECDSA_SHA256 {
            Some(PySignatureAlgorithm::EcdsaSha256)
        } else if alg == &ECDSA_SHA384 {
            Some(PySignatureAlgorithm::EcdsaSha384)
        } else if alg == &ECDSA_SHA512 {
            Some(PySignatureAlgorithm::EcdsaSha512)
        } else if alg == &ED25519 {
            Some(PySignatureAlgorithm::Ed25519)
        } else if alg == &ED448 {
            Some(PySignatureAlgorithm::Ed448)
        } else {
            None
        }
    }
}
