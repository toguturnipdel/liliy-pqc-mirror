#include <openssl/provider.h>
#include <spdlog/spdlog.h>

#include <lily/crypto/OQSLoader.h>

using namespace lily::core;

// OQS provider init entrypoint
extern "C" OSSL_provider_init_fn oqs_provider_init;

namespace lily::crypto
{
    Expect<void> loadOQSProvider()
    {
        if (!OSSL_PROVIDER_add_builtin(nullptr, "oqsprovider", &oqs_provider_init))
        {
            spdlog::error("Failed to initialize OQS provider to OpenSSL. Cause: OSSL_PROVIDER_add_builtin");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        if (!OSSL_PROVIDER_load(nullptr, "default"))
        {
            spdlog::error("Failed to load OpenSSL default provider. Cause: OSSL_PROVIDER_load");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        if (!OSSL_PROVIDER_load(nullptr, "oqsprovider"))
        {
            spdlog::error("Failed to load OQS provider. Cause: OSSL_PROVIDER_load");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }
        return success;
    }
} // namespace lily::crypto
