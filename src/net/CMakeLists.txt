# Create the library
add_library(lily-net STATIC 
    ServerListener.cpp
    ServerSession.cpp
    ClientConnection.cpp
)

# Link the required libraries
target_link_libraries(lily-net PRIVATE 
    lily-log
    Boost::asio
    Boost::outcome
    Boost::beast
    spdlog::spdlog
    oqsprovider
)
