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
     * The `NetworkListener` class provides functionality to listen on a specific port
     * and accept incoming connections. It can be used in server applications to set up
     * network communication.
     */
    class NetworkListener
    {
        std::unique_ptr<boost::beast::net::io_context> ioc;
        boost::asio::ssl::context ctx;
        boost::asio::ip::tcp::endpoint endpoint;
        boost::asio::ip::tcp::acceptor acceptor;

        /**
         * @brief Constructs the required object for a new `NetworkListener` instance.
         */
        NetworkListener(uint16_t port);

    public:
        NetworkListener(NetworkListener&& other):
            ioc(std::move(other.ioc)), ctx(std::move(other.ctx)), endpoint(std::move(other.endpoint)),
            acceptor(std::move(other.acceptor))
        {
        }
        NetworkListener& operator=(NetworkListener&& other)
        {
            this->ioc      = std::move(other.ioc);
            this->ctx      = std::move(other.ctx);
            this->endpoint = std::move(other.endpoint);
            this->acceptor = std::move(other.acceptor);
            return *this;
        }
        NetworkListener(NetworkListener const&)            = delete;
        NetworkListener& operator=(NetworkListener const&) = delete;

        /**
         * @brief Constructs a new `NetworkListener` instance.
         *
         * @param port The port number to listen on.
         */
        static core::Expect<NetworkListener> create(uint16_t port, std::filesystem::path const& serverCertificatePath,
                                                    std::filesystem::path const& privateKeyPath);

        /**
         * @brief Starts listening for incoming connections.
         *
         * This method initializes the network listener and begins accepting incoming
         * connections. It should be called after constructing an instance of
         * `NetworkListener`.
         */
        void run();
    };
} // namespace lily::net
