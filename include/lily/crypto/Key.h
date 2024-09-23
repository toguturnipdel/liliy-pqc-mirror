#pragma once

#include <filesystem>
#include <optional>

#include <lily/core/ErrorCode.h>

namespace lily::crypto
{
    /**
     * @brief Generates a post-quantum cryptography (PQC) keypair.
     *
     * This function creates a public and private keypair suitable for use
     * in post-quantum cryptographic algorithms. The generated keys can
     * be used for secure communications resistant to quantum attacks.
     */
    core::Expect<std::string> generatePQCKey(std::string const& algoName,
                                             std::optional<std::filesystem::path> const& outputPath = std::nullopt);

    /**
     * @brief Generates a post-quantum cryptography (PQC) certificate.
     *
     * This function creates a digital certificate based on post-quantum
     * cryptographic principles, ensuring secure identity verification in
     * a quantum-resistant manner. The certificate is signed using the
     * provided private key and includes the associated public key.
     */
    core::Expect<std::string>
        generateSelfSignedPQCCert(std::string const& privateKey,
                                  std::optional<std::filesystem::path> const& outputPath = std::nullopt);
} // namespace lily::crypto
