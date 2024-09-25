#include <CLI/CLI.hpp>
#include <cstdlib>
#include <fmt/color.h>
#include <fmt/core.h>
#include <thread>

#include <lily/crypto/Key.h>
#include <lily/crypto/OQSLoader.h>
#include <lily/net/ClientConnection.h>
#include <lily/net/ServerListener.h>

using namespace lily::core;
using namespace lily::crypto;
using namespace lily::net;

int32_t main(int32_t argc, char** argv)
{
    // Load OQS provider to OpenSSL
    if (!loadOQSProvider())
        return EXIT_FAILURE;

    // Main CLI commands
    CLI::App main {"Lily-PQC main commands"};

    // Handle `main run-server` execution
    auto mainRunServer {main.add_subcommand("server-run", "Run application as server")};
    std::filesystem::path certificateFile {};
    std::filesystem::path privateKeyFile {};
    uint16_t port {};
    {
        mainRunServer
            ->add_option("--certificate-file", certificateFile,
                         "The absolute path to the server's certificate file, in PEM format")
            ->required()
            ->check(CLI::ExistingFile);
        mainRunServer
            ->add_option("--private-key-file", privateKeyFile,
                         "The absolute path to the server's private key file, in PEM format")
            ->required()
            ->check(CLI::ExistingFile);
        mainRunServer->add_option("--port", port, "The server listener port")->required()->check(CLI::PositiveNumber);
        mainRunServer->callback(
            [&]
            {
                // Initialize the server with its configuration
                auto outcomeListener {ServerListener::create(port, certificateFile, privateKeyFile)};
                if (!outcomeListener)
                    return std::exit(EXIT_FAILURE);
                auto listener {std::move(outcomeListener.assume_value())};

                fmt::print(fmt::fg(fmt::color::green), "[v] Listening to port {}...\r\n", port);

                // Listen to the given port
                listener.run();
            });
    }

    // Handle `main gen-pqc` execution
    auto mainGenKeyCert {main.add_subcommand(
        "gen-pqc",
        "Generate PQC Key and Certificate (only valid for DSA algorithm because it will generate a certificate)")};
    std::filesystem::path outputCertificateFile {};
    std::filesystem::path outputPrivateKeyFile {};
    std::string algoName {};
    {
        mainGenKeyCert
            ->add_option("--output-certificate-file", outputCertificateFile,
                         "The absolute path to the output certificate file (PEM format)")
            ->required()
            ->check(!CLI::ExistingFile);
        mainGenKeyCert
            ->add_option("--private-key-file", outputPrivateKeyFile,
                         "The absolute path to the output private key file (PEM format)")
            ->required()
            ->check(!CLI::ExistingFile);
        mainGenKeyCert
            ->add_option("--algo-name", algoName,
                         "The PQC algorithm name (only for DSA algorithm, such as dilithium5, p521_dilithium5)")
            ->required()
            ->check(CLI::TypeValidator<std::string> {});
        mainGenKeyCert->callback(
            [&]() -> Expect<void>
            {
                BOOST_OUTCOME_TRY(decltype(auto) privateKey, generatePQCKey(algoName, outputPrivateKeyFile));
                BOOST_OUTCOME_TRY(generateSelfSignedPQCCert(privateKey, outputCertificateFile));
                fmt::print(fmt::fg(fmt::color::green),
                           "[v] PQC keypair and certificate with algo `{}` successfully created!\r\n", algoName);
                return success;
            });
    }

    // Handle `main run-client` execution
    auto mainRunClient {main.add_subcommand("client-run", "Run application as client")};
    std::string serverHost {};
    uint16_t serverPort {};
    uint32_t concurrentNum {};
    std::string tlsGroup {};
    uint32_t dummyDataLength {};
    {
        mainRunClient->add_option("--server-host", serverHost, "The server host address (eg, 192.168.1.2)")
            ->required()
            ->check(CLI::TypeValidator<std::string> {});
        mainRunClient->add_option("--server-port", serverPort, "The server host port (eg, 7004)")
            ->required()
            ->check(CLI::PositiveNumber);
        mainRunClient->add_option("--concurrent-user", concurrentNum, "The number of concurrent user")
            ->required()
            ->check(CLI::PositiveNumber);
        mainRunClient->add_option("--tls-group", tlsGroup, "The TLS group used")
            ->required()
            ->check(CLI::TypeValidator<std::string> {});
        mainRunClient
            ->add_option("--data-length", dummyDataLength, "The size of the data to be transmitted to the server (in bytes)")
            ->required()
            ->check(CLI::PositiveNumber);
        mainRunClient->callback(
            [&]
            {
                // Record total request
                std::atomic_int64_t totalSuccessfulRequest {};
                std::atomic_int64_t totalFailedRequest {};

                // Set-up concurrent users pool
                std::vector<std::jthread> userThreads(concurrentNum);
                for (auto& thread: userThreads)
                    thread = std::jthread {
                        [&]
                        {
                            // Send dummy data repeatedly
                            while (true)
                            {
                                if (!ClientConnection::sendDummyData(serverHost, serverPort, tlsGroup, dummyDataLength))
                                    ++totalFailedRequest;
                                else
                                    ++totalSuccessfulRequest;
                            }
                        }};

                //
                std::jthread totalRequestPrinter {
                    [&]
                    {
                        auto startTime {std::chrono::high_resolution_clock::now()};

                        while (true)
                        {
                            std::this_thread::sleep_for(std::chrono::seconds {5});

                            auto elapsedTime {std::chrono::high_resolution_clock::now() - startTime};
                            fmt::print("[-] Successful Request: {} | Failed Request: {} | TPS : {:.2f} req/s\r\n",
                                       totalSuccessfulRequest.load(), totalFailedRequest.load(),
                                       static_cast<double>(totalSuccessfulRequest.load() + totalFailedRequest.load()) /
                                           std::chrono::duration_cast<std::chrono::seconds>(elapsedTime).count());
                        }
                    }};

                fmt::print(fmt::fg(fmt::color::green), "[v] All users is active and testing the server!\r\n");

                for (auto& thread: userThreads)
                    thread.join();
            });
    }

    CLI11_PARSE(main, argc, argv);

    return EXIT_SUCCESS;
}
