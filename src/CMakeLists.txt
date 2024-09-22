# Add the subdirectory
add_subdirectory(net)
add_subdirectory(crypto)

# Create the executable
add_executable(lily-pqc main.cpp)

# Link Boost and OpenSSL libraries
target_link_libraries(lily-pqc PRIVATE 
    lily-net
    lily-crypto
    Boost::boost
)
