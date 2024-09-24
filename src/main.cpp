#include <CLI/CLI.hpp>
#include <cstdlib>
#include <fmt/color.h>
#include <fmt/core.h>

#include <lily/crypto/Key.h>
#include <lily/crypto/OQSLoader.h>
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

    // Handle `main run` execution
    auto mainRun {main.add_subcommand("run", "Run application")};
    {
        std::filesystem::path certificateFile {};
        std::filesystem::path privateKeyFile {};
        uint16_t port {};

        mainRun
            ->add_option("--certificate-file", certificateFile,
                         "The absolute path to the server's certificate file, in PEM format")
            ->required()
            ->check(CLI::ExistingFile);
        mainRun
            ->add_option("--private-key-file", privateKeyFile,
                         "The absolute path to the server's private key file, in PEM format")
            ->required()
            ->check(CLI::ExistingFile);
        mainRun->add_option("--port", port, "The server listener port")->required()->check(CLI::PositiveNumber);
        mainRun->callback(
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
    {
        std::filesystem::path outputCertificateFile {};
        std::filesystem::path outputPrivateKeyFile {};
        std::string algoName {};

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
            ->check(!CLI::ExistingFile);
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

    CLI11_PARSE(main, argc, argv);

    return EXIT_SUCCESS;
}
