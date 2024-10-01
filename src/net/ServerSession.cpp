#include <chrono>
#include <fmt/chrono.h>
#include <fmt/core.h>
#include <fstream>
#include <spdlog/spdlog.h>

#include <lily/core/ErrorCode.h>
#include <lily/log/ServerLog.h>
#include <lily/net/ServerSession.h>

using namespace lily::core;
using namespace lily::log;

namespace lily::net
{
    void ServerSession::run()
    {
        // Variable that collect the error code thrown by boost function
        boost::beast::error_code ec {};

        // Set the timeout.
        boost::beast::get_lowest_layer(this->stream).expires_never();

        // Perform the SSL handshake and measure the handshake time using `std::chrono`. This will measure the whole
        // handshake process duration.
        auto beginHandshakeTime {std::chrono::high_resolution_clock::now()};
        this->stream.handshake(boost::asio::ssl::stream_base::server, ec);
        auto handshakeDuration {std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::high_resolution_clock::now() - beginHandshakeTime)
                                    .count()};
        if (ec)
        {
            if (ec != boost::beast::net::ssl::error::stream_truncated and ec != boost::asio::error::broken_pipe and
                ec != boost::asio::error::connection_reset)
                return spdlog::error("Lily-PQC server SSL handshake with client failed! Why: {}", ec.message());
            return;
        }

        while (true)
        {
            boost::beast::http::request<boost::beast::http::string_body> req {};

            // Perform the SSL read and measure the duration
            auto beginReadTime {std::chrono::high_resolution_clock::now()};
            auto readSize {boost::beast::http::read(this->stream, this->buffer, req, ec)};
            auto readDuration {std::chrono::duration_cast<std::chrono::microseconds>(
                                   std::chrono::high_resolution_clock::now() - beginReadTime)
                                   .count()};
            if (ec == boost::beast::http::error::end_of_stream)
                break;
            if (ec)
                return;

            // Handle request
            boost::beast::http::message_generator msg {
                [](boost::beast::http::request<boost::beast::http::string_body>&& req)
                    -> boost::beast::http::message_generator
                {
                    // Create empty HTTP response
                    boost::beast::http::response<boost::beast::http::string_body> res {
                        boost::beast::http::status::bad_request, req.version()};
                    res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
                    res.set(boost::beast::http::field::content_type, "text/plain");
                    res.set(boost::beast::http::field::connection, req.keep_alive() ? "keep-alive" : "close");
                    res.keep_alive(req.keep_alive());

                    // Echo the body sent by the client
                    res.body().assign(std::move(req.body()));
                    res.prepare_payload();
                    return res;
                }(std::move(req))};

            // Determine if we should close the connection
            bool keep_alive {msg.keep_alive()};

            // Send the response
            auto beginWriteTime {std::chrono::high_resolution_clock::now()};
            auto writeSize {boost::beast::write(this->stream, std::move(msg), ec)};
            auto writeDuration {std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::high_resolution_clock::now() - beginWriteTime)
                                    .count()};
            if (ec)
            {
                if (ec != boost::beast::net::ssl::error::stream_truncated and ec != boost::asio::error::broken_pipe and
                    ec != boost::asio::error::connection_reset)
                    return spdlog::error("Lily-PQC server SSL write to client failed! Why: {}", ec.message());
                return;
            }

            // Log server SSL performance
            ServerLog::getInstance().write(handshakeDuration, readSize, readDuration, writeSize, writeDuration);

            if (!keep_alive)
            {
                // This means we should close the connection, usually because
                // the response indicated the "Connection: close" semantic.
                break;
            }
        }

        // Perform the SSL shutdown
        return this->close();
    }

    void ServerSession::close()
    {
        // Variable that collect the error code thrown by boost function
        boost::beast::error_code ec {};

        // Perform the SSL shutdown
        this->stream.shutdown(ec);
        if (ec)
        {
            if (ec != boost::beast::net::ssl::error::stream_truncated and ec != boost::asio::error::broken_pipe and
                ec != boost::asio::error::connection_reset)
                return spdlog::error("Lily-PQC server SSL shutdown to client failed! Why: {}", ec.message());
        }
    }
} // namespace lily::net