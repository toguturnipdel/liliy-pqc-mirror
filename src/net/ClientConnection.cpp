#include <spdlog/spdlog.h>

#include <lily/core/Constants.h>
#include <lily/log/ClientLog.h>
#include <lily/net/ClientConnection.h>

using namespace lily::core;
using namespace lily::log;

namespace lily::net
{
    ClientConnection::ClientConnection():
        ioc(std::make_unique<boost::beast::net::io_context>()), ctx {boost::asio::ssl::context::tlsv13_client}
    {
    }

    ClientConnection::ClientConnection(ClientConnection&& other): ioc(std::move(other.ioc)), ctx(std::move(other.ctx))
    {
    }

    ClientConnection& ClientConnection::operator=(ClientConnection&& other)
    {
        this->ioc = std::move(other.ioc);
        this->ctx = std::move(other.ctx);
        return *this;
    }

    Expect<void> ClientConnection::sendDummyData(std::string const& serverHost, uint16_t serverPort,
                                                 std::string const& tlsGroup, uint32_t dummyDataLength)
    {
        ClientConnection connection {};

        // Variable that collect the error code thrown by boost function
        boost::beast::error_code ec {};

        // Disable the verification. The verification will only be necessary for mutual TLS.
        std::ignore = connection.ctx.set_verify_mode(boost::asio::ssl::verify_none, ec);
        if (ec)
        {
            spdlog::error("Lily-PQC client context set_verify_mode failed! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Force the client to use TLS1.3
        SSL_CTX_set_min_proto_version(connection.ctx.native_handle(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(connection.ctx.native_handle(), TLS1_3_VERSION);

        // Set the key exchange algorithm
        if (SSL_CTX_set1_groups_list(connection.ctx.native_handle(), tlsGroup.c_str()) <= 0)
        {
            spdlog::error("Lily-PQC client context set key exchange algorithm failed! Cause: SSL_CTX_set1_groups_list");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Set the supported signature algorithm
        if (SSL_CTX_set1_sigalgs_list(connection.ctx.native_handle(), constants::SUPPORTED_SIGALGS_LIST) <= 0)
        {
            spdlog::error(
                "Lily-PQC client context set supported signature algorithm failed! Cause: SSL_CTX_set1_sigalgs_list");
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // These objects perform our I/O
        boost::asio::ip::tcp::resolver resolver {*connection.ioc.get()};
        boost::asio::ssl::stream<boost::beast::tcp_stream> stream {*connection.ioc.get(), connection.ctx};

        // Look up the domain name
        auto resolvedServer {resolver.resolve(serverHost, fmt::format("{}", serverPort), ec)};
        if (ec)
        {
            spdlog::error("Lily-PQC client failed to resolve server! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Make the connection on the IP address we get from a lookup
        std::ignore = boost::beast::get_lowest_layer(stream).connect(resolvedServer, ec);
        if (ec)
        {
            if (ec != boost::asio::error::connection_refused and ec != boost::beast::net::ssl::error::stream_truncated)
            {
                spdlog::error("Lily-PQC client connection to server failed! Why: {}", ec.message());
                return ErrorCode::LILY_ERRORCODE_EXPECTED;
            }
            return ErrorCode::LILY_ERRORCODE_UNEXPECTED;
        }

        // Perform the SSL handshake
        auto beginHandshakeTime {std::chrono::high_resolution_clock::now()};
        std::ignore = stream.handshake(boost::asio::ssl::stream_base::client, ec);
        auto handshakeDuration {std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::high_resolution_clock::now() - beginHandshakeTime)
                                    .count()};
        if (ec)
        {
            if (ec != boost::beast::net::ssl::error::stream_truncated and ec != boost::asio::error::broken_pipe and
                ec != boost::asio::error::connection_reset)
            {
                spdlog::error("Lily-PQC client SSL handshake with server failed! Why: {}", ec.message());
                return ErrorCode::LILY_ERRORCODE_EXPECTED;
            }
            return ErrorCode::LILY_ERRORCODE_UNEXPECTED;
        }

        // Set up an HTTP GET request message
        boost::beast::http::request<boost::beast::http::string_body> req {boost::beast::http::verb::post, "/", 11};
        req.set(boost::beast::http::field::host, serverHost);
        req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(boost::beast::http::field::content_type, "text/plain");
        req.keep_alive(false);

        // Create dummy body with the given size
        req.body().assign(dummyDataLength, 'A');
        req.prepare_payload();

        // Send the HTTP request to the remote host
        auto beginWriteTime {std::chrono::high_resolution_clock::now()};
        auto writeSize {boost::beast::http::write(stream, req, ec)};
        auto writeDuration {std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::high_resolution_clock::now() - beginWriteTime)
                                .count()};
        if (ec)
        {
            spdlog::error("Lily-PQC client SSL write to server failed! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // This buffer is used for reading and must be persisted
        boost::beast::flat_buffer buffer {};

        // Declare a container to hold the response
        boost::beast::http::response<boost::beast::http::dynamic_body> res {};

        // Receive the HTTP response
        auto beginReadTime {std::chrono::high_resolution_clock::now()};
        auto readSize {boost::beast::http::read(stream, buffer, res, ec)};
        auto readDuration {std::chrono::duration_cast<std::chrono::microseconds>(
                               std::chrono::high_resolution_clock::now() - beginReadTime)
                               .count()};
        if (ec)
        {
            spdlog::error("Lily-PQC client SSL read from server failed! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        // Log server SSL performance
        ClientLog::getInstance().write(handshakeDuration, writeSize, writeDuration, readSize, readDuration);

        // Gracefully close the stream
        stream.shutdown(ec);
        if (ec and ec != boost::beast::net::ssl::error::stream_truncated)
        {
            spdlog::error("Lily-PQC client SSL shutdown to server failed! Why: {}", ec.message());
            return ErrorCode::LILY_ERRORCODE_EXPECTED;
        }

        return success;
    }
} // namespace lily::net
