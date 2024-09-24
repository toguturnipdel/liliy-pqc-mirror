# Include FetchContent tools
include(FetchContent)

# Find OpenSSL and Boost using Vcpkg
find_package(OpenSSL REQUIRED GLOBAL)
find_package(spdlog REQUIRED GLOBAL)
find_package(Boost
    REQUIRED GLOBAL
    COMPONENTS
        asio outcome beast
)
find_package(fmt REQUIRED GLOBAL)
find_package(CLI11 REQUIRED GLOBAL)

# liboqs
# Configure the liboqs
execute_process(
    COMMAND cmake
            -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE} 
            -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=${CMAKE_EXPORT_COMPILE_COMMANDS} 
            -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER} 
            -DCMAKE_CXX_COMPILER:FILEPATH=${CMAKE_CXX_COMPILER}
            -DOPENSSL_ROOT_DIR:FILEPATH=${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}
            -DOQS_BUILD_ONLY_LIB:BOOL=ON
            --no-warn-unused-cli 
            -S${CMAKE_CURRENT_SOURCE_DIR}/liboqs
            -B${CMAKE_CURRENT_BINARY_DIR}/liboqs
            -G${CMAKE_GENERATOR}
    ECHO_OUTPUT_VARIABLE
    ECHO_ERROR_VARIABLE
    COMMAND_ERROR_IS_FATAL ANY
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
# Build the liboqs
execute_process(
    COMMAND cmake
            --build ${CMAKE_CURRENT_BINARY_DIR}/liboqs
            --config ${CMAKE_BUILD_TYPE} 
            --target oqs
    ECHO_OUTPUT_VARIABLE
    ECHO_ERROR_VARIABLE
    COMMAND_ERROR_IS_FATAL ANY
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
# Install the liboqs
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/liboqs/install)
execute_process(
    COMMAND cmake
            --install ${CMAKE_CURRENT_BINARY_DIR}/liboqs
            --config ${CMAKE_BUILD_TYPE}
            --prefix ${CMAKE_CURRENT_BINARY_DIR}/liboqs/install
    ECHO_OUTPUT_VARIABLE
    ECHO_ERROR_VARIABLE
    COMMAND_ERROR_IS_FATAL ANY
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# qsc-key-encoder
add_subdirectory(qsc-key-encoder)
set_target_properties(qsc_key_encoder_test
    PROPERTIES
    EXCLUDE_FROM_ALL true
)

# oqs-provider
set(OQS_PROVIDER_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(OQS_KEM_ENCODERS ON CACHE BOOL "" FORCE)
set(liboqs_DIR "${CMAKE_CURRENT_BINARY_DIR}/liboqs/install/lib/cmake/liboqs" CACHE STRING "" FORCE)
add_subdirectory(oqs-provider)
