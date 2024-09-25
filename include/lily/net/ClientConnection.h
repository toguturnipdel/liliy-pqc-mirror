#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>

#include <lily/core/ErrorCode.h>

namespace lily::net
{
    class ClientConnection
    {
    private:
        std::unique_ptr<boost::beast::net::io_context> ioc;
        boost::asio::ssl::context ctx;

        ClientConnection();
        ClientConnection(ClientConnection const&)            = delete;
        ClientConnection& operator=(ClientConnection const&) = delete;

    public:
        ClientConnection(ClientConnection&& other);
        ClientConnection& operator=(ClientConnection&& other);
        static core::Expect<void> sendDummyData(std::string const& serverHost, uint16_t serverPort,
                                                std::string const& tlsGroup, uint32_t dummyDataLength);
    };
} // namespace lily::net
