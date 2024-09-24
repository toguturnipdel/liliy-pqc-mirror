# Create the library
add_library(lily-log STATIC 
    ClientLog.cpp
    ServerLog.cpp
)

# Link the required libraries
target_link_libraries(lily-log PRIVATE 
    spdlog::spdlog
)
