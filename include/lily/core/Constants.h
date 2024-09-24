#pragma once

namespace lily::core::constants
{
    static constexpr char const* DEFAULT_SERVER_HOST {"0.0.0.0"};
    static constexpr char const* SUPPORTED_SIGALGS_LIST {
        // Supported classical algorithms
        "RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA384:ECDSA+SHA512:"
        // Supported PQC algorithms
        "dilithium2:p256_dilithium2:rsa3072_dilithium2:dilithium3:p384_dilithium3:dilithium5:p521_dilithium5:mldsa44:p256_mldsa44:rsa3072_mldsa44:mldsa44_pss2048:mldsa44_rsa2048:mldsa44_ed25519:mldsa44_p256:mldsa44_bp256:mldsa65:p384_mldsa65:mldsa65_pss3072:mldsa65_rsa3072:mldsa65_p256:mldsa65_bp256:mldsa65_ed25519:mldsa87:p521_mldsa87:mldsa87_p384:mldsa87_bp384:mldsa87_ed448:falcon512:p256_falcon512:rsa3072_falcon512:falconpadded512:p256_falconpadded512:rsa3072_falconpadded512:falcon1024:p521_falcon1024:falconpadded1024:p521_falconpadded1024:sphincssha2128fsimple:p256_sphincssha2128fsimple:rsa3072_sphincssha2128fsimple:sphincssha2128ssimple:p256_sphincssha2128ssimple:rsa3072_sphincssha2128ssimple:sphincssha2192fsimple:p384_sphincssha2192fsimple:sphincsshake128fsimple:p256_sphincsshake128fsimple:rsa3072_sphincsshake128fsimple:mayo1:p256_mayo1:mayo2:p256_mayo2:mayo3:p384_mayo3:mayo5:p521_mayo5"
    };
    static constexpr char const* SUPPORTED_PQC_GROUPS_LIST {
        "frodo640aes:p256_frodo640aes:x25519_frodo640aes:frodo640shake:p256_frodo640shake:x25519_frodo640shake:frodo976aes:p384_frodo976aes:x448_frodo976aes:frodo976shake:p384_frodo976shake:x448_frodo976shake:frodo1344aes:p521_frodo1344aes:frodo1344shake:p521_frodo1344shake:kyber512:p256_kyber512:x25519_kyber512:kyber768:p384_kyber768:x448_kyber768:x25519_kyber768:p256_kyber768:kyber1024:p521_kyber1024:mlkem512:p256_mlkem512:x25519_mlkem512:mlkem768:p384_mlkem768:x448_mlkem768:x25519_mlkem768:p256_mlkem768:mlkem1024:p521_mlkem1024:p384_mlkem1024:bikel1:p256_bikel1:x25519_bikel1:bikel3:p384_bikel3:x448_bikel3:bikel5:p521_bikel5:hqc128:p256_hqc128:x25519_hqc128:hqc192:p384_hqc192:x448_hqc192:hqc256:p521_hqc256"};
} // namespace lily::core::constants
