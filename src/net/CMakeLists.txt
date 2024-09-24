# Create the library
add_library(lily-net STATIC 
    ServerListener.cpp
    ServerSession.cpp
)

# Link the required libraries
target_link_libraries(lily-net PRIVATE 
    Boost::boost
    spdlog::spdlog
    oqsprovider
)
