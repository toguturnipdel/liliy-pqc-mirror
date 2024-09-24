#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <filesystem>

#include <lily/core/ErrorCode.h>

namespace lily::net
{
    /**
     * @brief Represents a network listener for handling incoming connections.
     *
     * The `ServerListener` class provides functionality to listen on a specific port
     * and accept incoming connections. It can be used in server applications to set up
     * network communication.
     */
    class ServerListener
    {
        std::unique_ptr<boost::beast::net::io_context> ioc;
        boost::asio::ssl::context ctx;
        boost::asio::ip::tcp::endpoint endpoint;
        boost::asio::ip::tcp::acceptor acceptor;

        /**
         * @brief Constructs the required object for a new `ServerListener` instance.
         */
        ServerListener(uint16_t port);

    public:
        ServerListener(ServerListener&& other):
            ioc(std::move(other.ioc)), ctx(std::move(other.ctx)), endpoint(std::move(other.endpoint)),
            acceptor(std::move(other.acceptor))
        {
        }
        ServerListener& operator=(ServerListener&& other)
        {
            this->ioc      = std::move(other.ioc);
            this->ctx      = std::move(other.ctx);
            this->endpoint = std::move(other.endpoint);
            this->acceptor = std::move(other.acceptor);
            return *this;
        }
        ServerListener(ServerListener const&)            = delete;
        ServerListener& operator=(ServerListener const&) = delete;

        /**
         * @brief Constructs a new `ServerListener` instance.
         *
         * @param port The port number to listen on.
         */
        static core::Expect<ServerListener> create(uint16_t port, std::filesystem::path const& serverCertificatePath,
                                                   std::filesystem::path const& privateKeyPath);

        /**
         * @brief Starts listening for incoming connections.
         *
         * This method initializes the network listener and begins accepting incoming
         * connections. It should be called after constructing an instance of
         * `ServerListener`.
         */
        void run();
    };
} // namespace lily::net
