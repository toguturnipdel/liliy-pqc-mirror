# Create the library
add_library(lily-net STATIC 
    NetworkListener.cpp
    NetworkSession.cpp
)

# Link the required libraries
target_link_libraries(lily-net PRIVATE 
    Boost::boost
    spdlog::spdlog
)
