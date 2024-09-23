#include <fstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <spdlog/spdlog.h>

#include <lily/crypto/Key.h>

using namespace lily::core;

namespace lily::crypto
{
    Expect<std::string> generatePQCKey(std::string const& algoName,
                                       std::optional<std::filesystem::path> const& outputPath)
    {
        // Generate EVP_PKEY_CTX opaque object using the algorithm name
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx {
            EVP_PKEY_CTX_new_from_name(nullptr, algoName.data(), nullptr), EVP_PKEY_CTX_free};
        if (ctx == nullptr)
        {
            spdlog::error("Invalid PQC algorithm name");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Initialize PQC keypair generator
        if (EVP_PKEY_keygen_init(ctx.get()) != 1)
        {
            spdlog::error("Failed to initialize PQC keypair generator");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Generate the keypair
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key {nullptr, EVP_PKEY_free};
        auto keyPtr {key.get()};
        if (EVP_PKEY_generate(ctx.get(), &keyPtr) != 1)
        {
            spdlog::error("Failed to generate PQC keypair");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }
        key.reset(keyPtr);

        // Create the BIO as the private key stream
        std::unique_ptr<BIO, decltype(&BIO_free)> privateKeyBIO {BIO_new(BIO_s_mem()), BIO_free};
        if (!privateKeyBIO)
        {
            spdlog::error("Failed to create private key BIO");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Write the private key to the BIO stream
        if (PEM_write_bio_PrivateKey(privateKeyBIO.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) <= 0)
        {
            spdlog::error("Failed to write private key to BIO");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Write the private key from BIO stream to `std::string`
        BUF_MEM* bptr {};
        BIO_get_mem_ptr(privateKeyBIO.get(), &bptr);
        std::string output {bptr->data, bptr->length};

        // Write to output path if its given
        if (outputPath)
        {
            std::ofstream outputStream {};
            try
            {
                outputStream.open(outputPath.value());
                if (!outputStream.is_open())
                {
                    spdlog::error("Failed to create output file");
                    return ErrorCode::LILY_ERRORCODE_EXPECTED;
                }
                outputStream.write(output.data(), output.size());
            }
            catch (std::exception const& e)
            {
                spdlog::error("Failed to create output file. Why: {}", e.what());
                return ErrorCode::LILY_ERRORCODE_EXPECTED;
            }
        }

        return {bptr->data, bptr->length};
    }

    Expect<std::string> generateSelfSignedPQCCert(std::string const& privateKey,
                                                  std::optional<std::filesystem::path> const& outputPath)
    {
        // Generate X509 opaque object using the algorithm name
        std::unique_ptr<X509, decltype(&X509_free)> cert {X509_new(), X509_free};
        if (!cert)
        {
            spdlog::error("Failed to create X509 opaque object");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Set X509 version to 3. Version 3 addresses some of the security concerns and limited flexibility that were
        // issues in versions 1 and 2.
        if (X509_set_version(cert.get(), 3) <= 0)
        {
            spdlog::error("Failed to set X509 version to 3");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // The serial number of the certificate is part of the original X509 protocol. The serial number is a unique
        // number issued by the certificate issuer. But in this case, won't matter if its hard coded.
        if (ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) <= 0)
        {
            spdlog::error("Failed to set X509 serial number");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        //
        std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name {X509_NAME_new(), X509_NAME_free};
        if (!name)
        {
            spdlog::error("Unable to create X509_NAME structure");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        //
        static constexpr std::string_view DEFAULT_CN {"lily-pqc.com"};
        if (X509_NAME_add_entry_by_txt(name.get(), SN_commonName, MBSTRING_UTF8,
                                       reinterpret_cast<uint8_t const*>(DEFAULT_CN.data()), DEFAULT_CN.size(), -1,
                                       0) <= 0)
        {
            spdlog::error("Failed to assign common name to certificate");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        //
        if (X509_set_subject_name(cert.get(), name.get()) <= 0)
        {
            spdlog::error("Failed to set subject name");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        //
        if (X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get())) <= 0)
        {
            spdlog::error("Failed to set issuer name");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // 
        if (!X509_gmtime_adj(X509_get_notBefore(cert.get()), 0))
        {
            spdlog::error("Failed to set validity period");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // 
        if (!X509_gmtime_adj(X509_get_notAfter(cert.get()), 3'122'064'000)) // 99 years
        {
            spdlog::error("Failed to set validity period");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        //
        std::unique_ptr<BIO, decltype(&BIO_free)> privateKeyBIO {BIO_new_mem_buf(privateKey.data(), privateKey.size()),
                                                                 BIO_free};
        if (!privateKeyBIO)
        {
            spdlog::error("Failed to load private key as BIO stream");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        //
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> privateKeyPtr {
            PEM_read_bio_PrivateKey(privateKeyBIO.get(), nullptr, nullptr, nullptr), EVP_PKEY_free};
        if (!privateKeyPtr)
        {
            spdlog::error("Failed to read private key BIO stream to EVP_PKEY object");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        //
        if (X509_set_pubkey(cert.get(), privateKeyPtr.get()) <= 0)
        {
            spdlog::error("Failed to set public key in X509");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        //
        if (X509_sign(cert.get(), privateKeyPtr.get(), nullptr) <= 0)
        {
            spdlog::error("Failed to self sign certificate");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Create the BIO as the certificate stream
        std::unique_ptr<BIO, decltype(&BIO_free)> certificateBIO {BIO_new(BIO_s_mem()), BIO_free};
        if (!certificateBIO)
        {
            spdlog::error("Failed to create certificate BIO");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Write the certificate to the BIO stream
        if (PEM_write_bio_X509(certificateBIO.get(), cert.get()) <= 0)
        {
            spdlog::error("Failed to write certificate to BIO");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Write the certificate from BIO stream to `std::string`
        BUF_MEM* bptr {};
        BIO_get_mem_ptr(certificateBIO.get(), &bptr);
        std::string output {bptr->data, bptr->length};

        // Write to output path if its given
        if (outputPath)
        {
            std::ofstream outputStream {};
            try
            {
                outputStream.open(outputPath.value());
                if (!outputStream.is_open())
                {
                    spdlog::error("Failed to create output file");
                    return ErrorCode::LILY_ERRORCODE_EXPECTED;
                }
                outputStream.write(output.data(), output.size());
            }
            catch (std::exception const& e)
            {
                spdlog::error("Failed to create output file. Why: {}", e.what());
                return ErrorCode::LILY_ERRORCODE_EXPECTED;
            }
        }

        return output;
    }
} // namespace lily::crypto
