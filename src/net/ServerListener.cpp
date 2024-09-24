#include <spdlog/spdlog.h>
#include <thread>

#include <lily/core/Constants.h>
#include <lily/crypto/OQSLoader.h>
#include <lily/net/ServerListener.h>
#include <lily/net/ServerSession.h>

using namespace lily::core;

namespace lily::net
{
    ServerListener::ServerListener(uint16_t port):
        ioc {std::make_unique<boost::beast::net::io_context>(1)}, ctx {boost::asio::ssl::context::tlsv13_server},
        endpoint {boost::asio::ip::make_address(constants::DEFAULT_SERVER_HOST), port}, acceptor {*ioc.get()}
    {
    }

    Expect<ServerListener> ServerListener::create(uint16_t port, std::filesystem::path const& serverCertificatePath,
                                                  std::filesystem::path const& privateKeyPath)
    {
        // Create the `ServerListener` default instance
        ServerListener listener {port};

        // Variable that collect the error code thrown by boost function
        boost::beast::error_code ec {};

        // Open the socket communication
        std::ignore = listener.acceptor.open(listener.endpoint.protocol(), ec);
        if (ec)
        {
            spdlog::error("Lily-PQC server connection open failed! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Allow address reuse
        std::ignore = listener.acceptor.set_option(boost::beast::net::socket_base::reuse_address(true), ec);
        if (ec)
        {
            spdlog::error("Lily-PQC server connection set_option failed! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Bind to the server address
        std::ignore = listener.acceptor.bind(listener.endpoint, ec);
        if (ec)
        {
            spdlog::error("Lily-PQC server connection bind failed! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Start listening for connections
        std::ignore = listener.acceptor.listen(boost::beast::net::socket_base::max_listen_connections, ec);
        if (ec)
        {
            spdlog::error("Lily-PQC server connection listen failed! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Load the certificate
        std::ignore = listener.ctx.use_certificate_chain_file(serverCertificatePath, ec);
        if (ec)
        {
            spdlog::error("Lily-PQC server context use_certificate_chain_file failed! Why: {}\r\n", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Load the private key
        std::ignore = listener.ctx.use_private_key_file(privateKeyPath, boost::asio::ssl::context::pem, ec);
        if (ec)
        {
            spdlog::error("Lily-PQC server context use_certificate_chain_file failed! Why: {}\r\n", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Check whether the private key and certificate match or not
        if (SSL_CTX_check_private_key(listener.ctx.native_handle()) <= 0)
        {
            spdlog::error("Lily-PQC server private key and certificate mismatch! Cause: SSL_CTX_check_private_key");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Disable the verification. The verification will only be necessary for mutual TLS.
        std::ignore = listener.ctx.set_verify_mode(boost::asio::ssl::verify_none, ec);
        if (ec)
        {
            spdlog::error("Lily-PQC server context set_verify_mode failed! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Configure the session id to avoid undefined session id context
        constexpr std::array<uint8_t, SSL_MAX_SID_CTX_LENGTH> sessionId {};
        if (SSL_CTX_set_session_id_context(listener.ctx.native_handle(), sessionId.data(), sessionId.size()) <= 0)
        {
            spdlog::error("Lily-PQC server context set_session_id_context failed!");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Only allow TLS 1.3 for communication
        SSL_CTX_set_options(listener.ctx.native_handle(),
                            SSL_OP_ALLOW_CLIENT_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
        SSL_CTX_set_min_proto_version(listener.ctx.native_handle(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(listener.ctx.native_handle(), TLS1_3_VERSION);

        // Set the key exchange algorithm
        if (SSL_CTX_set1_groups_list(listener.ctx.native_handle(), constants::SUPPORTED_PQC_GROUPS_LIST) <= 0)
        {
            spdlog::error("Lily-PQC server context set key exchange algorithm failed! Cause: SSL_CTX_set1_groups_list");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Set the supported signature algorithm
        if (SSL_CTX_set1_sigalgs_list(listener.ctx.native_handle(), constants::SUPPORTED_SIGALGS_LIST) <= 0)
        {
            spdlog::error(
                "Lily-PQC server context set supported signature algorithm failed! Cause: SSL_CTX_set1_sigalgs_list");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        return listener;
    }

    void ServerListener::run()
    {
        // Variable that collect the error code thrown by boost function
        boost::beast::error_code ec {};

        while (true)
        {
            // This will receive the new connection
            boost::asio::ip::tcp::socket socket {this->ioc->get_executor()};

            // Block until we get a connection
            std::ignore = this->acceptor.accept(socket, ec);
            if (ec)
                spdlog::error("Lily-PQC server context accept failed! Why: {}", ec.message());

            std::jthread {std::bind(&ServerSession::run, ServerSession {std::move(socket), this->ctx})}.detach();
        }
    }
} // namespace lily::net
