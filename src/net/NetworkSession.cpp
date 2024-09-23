#include <chrono>
#include <fmt/core.h>
#include <fstream>
#include <spdlog/spdlog.h>

#include <lily/core/ErrorCode.h>
#include <lily/net/NetworkSession.h>

using namespace lily::core;

namespace lily::net
{
    namespace helper
    {
        // Record the bootstrap time for consistent log timestamp
        static auto BOOTSTRAP_TIME {std::chrono::high_resolution_clock::now()};

        /**
         * @brief A class to record and log the duration of SSL/TLS handshakes.
         */
        class HandshakeRecorder
        {
        private:
            std::ofstream stream;
            HandshakeRecorder()
            {
                this->stream.open(fmt::format(
                    "log_server_hs_{}.csv",
                    std::chrono::duration_cast<std::chrono::seconds>(BOOTSTRAP_TIME.time_since_epoch()).count()));
                if (!this->stream.is_open())
                {
                    spdlog::error("Failed to create handshake record log");
                    std::exit(EXIT_FAILURE);
                }
            }

            std::mutex mtx;

            HandshakeRecorder(HandshakeRecorder const&)            = delete;
            HandshakeRecorder(HandshakeRecorder&&)                 = delete;
            HandshakeRecorder& operator=(HandshakeRecorder const&) = delete;
            HandshakeRecorder& operator=(HandshakeRecorder&&)      = delete;

        public:
            static HandshakeRecorder& getInstance()
            {
                static HandshakeRecorder instance {};
                return instance;
            }

            void write(uint64_t time)
            {
                auto log {fmt::format("{}\r\n", time)};
                std::lock_guard lock {this->mtx};
                this->stream.write(log.c_str(), log.size());
            }
        };
    } // namespace helper

    void NetworkSession::run()
    {
        // Variable that collect the error code thrown by boost function
        boost::beast::error_code ec {};

        // Set the timeout.
        boost::beast::get_lowest_layer(this->stream).expires_never();

        // Perform the SSL handshake and measure the handshake time using `std::chrono`. This will measure the whole
        // handshake process duration.
        auto beginHandshakeTime {std::chrono::high_resolution_clock::now()};
        this->stream.handshake(boost::asio::ssl::stream_base::server, ec);
        auto totalHandshakeTime {std::chrono::high_resolution_clock::now() - beginHandshakeTime};
        if (ec)
            return spdlog::error("Client handshake failed! Why: {}", ec.message());

        // Log the SSL handshake duration
        auto handshakeDuration {std::chrono::duration_cast<std::chrono::milliseconds>(totalHandshakeTime).count()};
        fmt::print("[-] SSL handshake time: {} ms\r\n", handshakeDuration);
        helper::HandshakeRecorder::getInstance().write(handshakeDuration);

        while (true)
        {
            boost::beast::http::request<boost::beast::http::string_body> req {};

            // Perform the SSL read and measure the duration
            auto beginReadTime {std::chrono::high_resolution_clock::now()};
            boost::beast::http::read(this->stream, this->buffer, req, ec);
            auto totalReadTime {std::chrono::high_resolution_clock::now() - beginReadTime};
            if (ec == boost::beast::http::error::end_of_stream)
                break;
            if (ec)
                return;
            fmt::print("[-] SSL read time: {} ms\r\n",
                       std::chrono::duration_cast<std::chrono::milliseconds>(totalHandshakeTime).count());

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