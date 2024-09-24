#include <chrono>
#include <fmt/chrono.h>
#include <fmt/core.h>
#include <fstream>
#include <spdlog/spdlog.h>

#include <lily/core/ErrorCode.h>
#include <lily/net/ServerSession.h>

using namespace lily::core;

namespace lily::net
{
    namespace helper
    {
        // Record the bootstrap time for consistent log timestamp
        static auto BOOTSTRAP_TIME {std::time(nullptr)};

        /**
         * @brief A class to record and log the duration of SSL/TLS handshakes and SSL/TLS read.
         */
        class DurationRecorder
        {
        private:
            std::ofstream hsStream;
            std::ofstream rxStream;
            std::ofstream txStream;

            DurationRecorder()
            {
                //
                this->hsStream.open(fmt::format("{:%F_%T}_log_server_hs.csv", fmt::localtime(BOOTSTRAP_TIME)));
                if (!this->hsStream.is_open())
                {
                    spdlog::error("Failed to create handshake record log");
                    std::exit(EXIT_FAILURE);
                }
                static constexpr std::string_view HS_HEADER {"duration\r\n"};
                this->hsStream.write(HS_HEADER.data(), HS_HEADER.size());
                this->hsStream.flush();

                //
                this->rxStream.open(fmt::format("{:%F_%T}_log_server_rx.csv", fmt::localtime(BOOTSTRAP_TIME)));
                if (!this->rxStream.is_open())
                {
                    spdlog::error("Failed to create received data record log");
                    std::exit(EXIT_FAILURE);
                }
                static constexpr std::string_view RX_HEADER {"size;duration\r\n"};
                this->rxStream.write(RX_HEADER.data(), RX_HEADER.size());
                this->rxStream.flush();

                //
                this->txStream.open(fmt::format("{:%F_%T}_log_server_tx.csv", fmt::localtime(BOOTSTRAP_TIME)));
                if (!this->txStream.is_open())
                {
                    spdlog::error("Failed to create write data record log");
                    std::exit(EXIT_FAILURE);
                }
                static constexpr std::string_view TX_HEADER {"size;duration\r\n"};
                this->txStream.write(TX_HEADER.data(), TX_HEADER.size());
                this->txStream.flush();
            }

            // Synchronization mechanism
            std::mutex hsMtx;
            std::mutex rxMtx;
            std::mutex txMtx;

            DurationRecorder(DurationRecorder const&)            = delete;
            DurationRecorder(DurationRecorder&&)                 = delete;
            DurationRecorder& operator=(DurationRecorder const&) = delete;
            DurationRecorder& operator=(DurationRecorder&&)      = delete;

        public:
            static DurationRecorder& getInstance()
            {
                static DurationRecorder instance {};
                return instance;
            }

            /**
             * @brief Log the duration of SSL/TLS handshakes
             */
            void writeHsDuration(int64_t time)
            {
                auto log {fmt::format("{}\r\n", time)};
                std::lock_guard lock {this->hsMtx};
                this->hsStream.write(log.c_str(), log.size());
                this->hsStream.flush();
            }

            /**
             * @brief Log the size and duration of SSL/TLS read
             */
            void writeRxDuration(uint64_t size, int64_t time)
            {
                auto log {fmt::format("{};{}\r\n", size, time)};
                std::lock_guard lock {this->rxMtx};
                this->rxStream.write(log.c_str(), log.size());
                this->rxStream.flush();
            }

            /**
             * @brief Log the size and duration of SSL/TLS write
             */
            void writeTxDuration(uint64_t size, int64_t time)
            {
                auto log {fmt::format("{};{}\r\n", size, time)};
                std::lock_guard lock {this->txMtx};
                this->txStream.write(log.c_str(), log.size());
                this->txStream.flush();
            }
        };
    } // namespace helper

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
        auto totalHandshakeTime {std::chrono::high_resolution_clock::now() - beginHandshakeTime};
        if (ec)
            return spdlog::error("Client handshake failed! Why: {}", ec.message());

        // Log the SSL handshake duration
        auto handshakeDuration {std::chrono::duration_cast<std::chrono::milliseconds>(totalHandshakeTime).count()};
        fmt::print("[-] SSL handshake time: {} ms\r\n", handshakeDuration);
        helper::DurationRecorder::getInstance().writeHsDuration(handshakeDuration);

        while (true)
        {
            boost::beast::http::request<boost::beast::http::string_body> req {};

            // Perform the SSL read and measure the duration
            auto beginReadTime {std::chrono::high_resolution_clock::now()};
            auto readSize {boost::beast::http::read(this->stream, this->buffer, req, ec)};
            auto totalReadTime {std::chrono::high_resolution_clock::now() - beginReadTime};
            if (ec == boost::beast::http::error::end_of_stream)
                break;
            if (ec)
                return;

            // Log the SSL read size and duration
            auto readDuration {std::chrono::duration_cast<std::chrono::milliseconds>(totalReadTime).count()};
            fmt::print("[-] SSL read size: {} bytes, SSL read time: {} ms\r\n", readSize, readDuration);
            helper::DurationRecorder::getInstance().writeRxDuration(readSize, readDuration);

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
                    res.prepare_payload();
                    return res;
                }(std::move(req))};

            // Determine if we should close the connection
            bool keep_alive {msg.keep_alive()};

            // Send the response
            auto beginWriteTime {std::chrono::high_resolution_clock::now()};
            auto writeSize {boost::beast::write(this->stream, std::move(msg), ec)};
            auto totalWriteTime {std::chrono::high_resolution_clock::now() - beginWriteTime};
            if (ec)
                return spdlog::error("Client connection write failed! Why: {}", ec.message());

            // Log the SSL write size and duration
            auto writeDuration {std::chrono::duration_cast<std::chrono::milliseconds>(totalWriteTime).count()};
            fmt::print("[-] SSL write size: {} bytes, SSL write time: {} ms\r\n", writeSize, writeDuration);
            helper::DurationRecorder::getInstance().writeRxDuration(writeSize, writeDuration);

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
            return spdlog::error("Client connection shutdown failed! Why: {}", ec.message());
    }
} // namespace lily::net