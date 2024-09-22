#include <cstdlib>

#include <lily/crypto/OQSLoader.h>
#include <lily/net/NetworkListener.h>

using namespace lily::crypto;
using namespace lily::net;

int32_t main(int32_t argc, char** argv)
{
    // Load OQS provider to OpenSSL
    if (!loadOQSProvider())
        return EXIT_FAILURE;

    // Initialize the server with its configuration 
    auto outcomeListener {NetworkListener::create(8080, "", "")};
    if(!outcomeListener)
        return EXIT_FAILURE;
    auto listener {std::move(outcomeListener.assume_value())};

    // Listen to the given port
    listener.run();

    return EXIT_SUCCESS;
}
