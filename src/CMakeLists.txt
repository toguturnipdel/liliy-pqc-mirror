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

# Add pigpio include directories and link libraries
target_include_directories(lily-pqc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../external/pigpio)
target_link_libraries(lily-pqc PUBLIC pigpio)