#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http/message_generator.hpp>
#include <boost/beast/ssl.hpp>

namespace lily::net
{
    class ServerSession
    {
    private:
        boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
        boost::beast::flat_buffer buffer {};

    public:
        ServerSession(ServerSession&& other): stream(std::move(other.stream)), buffer(std::move(other.buffer)) {}
        ServerSession& operator=(ServerSession&& other)
        {
            this->stream = std::move(other.stream);
            this->buffer = std::move(other.buffer);
            return *this;
        }
        ServerSession(ServerSession const&)            = delete;
        ServerSession& operator=(ServerSession const&) = delete;

        // Take ownership of the socket
        ServerSession(boost::asio::ip::tcp::socket&& socket, boost::asio::ssl::context& ctx):
            stream(std::move(socket), ctx)
        {
        }

        // Start the synchronous operation
        void run();

        // Close the communication
        void close();
    };
} // namespace lily::net
