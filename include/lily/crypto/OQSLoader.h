#pragma once

#include <lily/core/ErrorCode.h>

namespace lily::crypto
{
    /**
     * @brief Initialize the OQS provider with OpenSSL.
     *
     * This function initializes the OQS provider, allowing you to use post-quantum cryptographic algorithms
     * provided by the Open Quantum Safe project in conjunction with OpenSSL.
     */
    core::Expect<void> loadOQSProvider();
} // namespace lily::crypto
