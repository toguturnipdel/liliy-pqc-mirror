#include <chrono>
#include <fmt/core.h>
#include <spdlog/spdlog.h>

#include <lily/core/ErrorCode.h>
#include <lily/net/NetworkSession.h>

using namespace lily::core;

namespace lily::net
{
    void NetworkSession::run()
    {
        // Variable that collect the error code thrown by boost function
        boost::beast::error_code ec {};

        // Set the timeout.
        boost::beast::get_lowest_layer(this->stream).expires_never();

        // Perform the SSL handshake and measure the handshake time using `std::chrono`. This will measure the time
        // elapsed to do the whole handshake process.
        auto beginHandshakeTime {std::chrono::high_resolution_clock::now()};
        this->stream.handshake(boost::asio::ssl::stream_base::server, ec);
        auto totalHandshakeTime {std::chrono::high_resolution_clock::now() - beginHandshakeTime};
        if (ec)
            return spdlog::error("Client handshake failed! Why: {}", ec.message());
        fmt::print("[-] SSL handshake time: {} ms\r\n",
                   std::chrono::duration_cast<std::chrono::milliseconds>(totalHandshakeTime).count());

        while (true)
        {
            boost::beast::http::request<boost::beast::http::string_body> req {};
            boost::beast::http::read(this->stream, this->buffer, req, ec);
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
                    res.set(boost::beast::http::field::content_type, "application/json");
                    res.set(boost::beast::http::field::connection, req.keep_alive() ? "keep-alive" : "close");
                    res.keep_alive(req.keep_alive());
                    res.prepare_payload();
                    return res;
                }(std::move(req))};

            // Determine if we should close the connection
            bool keep_alive {msg.keep_alive()};

            // Send the response
            boost::beast::write(this->stream, std::move(msg), ec);
            if (ec)
                return spdlog::error("Client connection write failed! Why: {}", ec.message());

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

    void NetworkSession::close()
    {
        // Variable that collect the error code thrown by boost function
        boost::beast::error_code ec {};

        // Perform the SSL shutdown
        this->stream.shutdown(ec);
        if (ec)
            return spdlog::error("Client connection shutdown failed! Why: {}", ec.message());
    }
} // namespace lily::net