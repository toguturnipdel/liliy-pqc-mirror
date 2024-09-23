# Create the library
add_library(lily-crypto STATIC 
    OQSLoader.cpp
    Key.cpp
)

# Link the required libraries
target_link_libraries(lily-crypto PRIVATE 
    oqsprovider
    OpenSSL::Crypto
    OpenSSL::SSL
    spdlog::spdlog
)
