# Add the subdirectory
add_subdirectory(crypto)
add_subdirectory(log)
add_subdirectory(net)

# Create the executable
add_executable(lily-pqc main.cpp)

# Link Boost and OpenSSL libraries
target_link_libraries(lily-pqc PRIVATE 
    lily-net
    lily-crypto
    Boost::asio
    Boost::outcome
    Boost::beast
    CLI11::CLI11
)

# Statically link libgcc and libstdc++
target_link_options(lily-pqc PRIVATE 
    -static-libgcc
    -static-libstdc++
)
