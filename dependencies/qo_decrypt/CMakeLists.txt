
cmake_minimum_required(VERSION 3.17)

#CMake Error at CMakeLists.txt:4 (project):
#  VERSION not allowed unless CMP0048 is set to NEW
if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()

message(STATUS "===================================================================")
message(STATUS "INFO: Module             : QODecrypt")
message(STATUS "INFO: CMAKE_SYSTEM_NAME  : ${CMAKE_SYSTEM_NAME}")
message(STATUS "INFO: CMAKE_SYSTEM       : ${CMAKE_SYSTEM}")
set(CMAKE_CXX_COMPILER_ID "GNU")
set(CMAKE_CXX_COMPILER_VERSION "10.2.1")
message(STATUS "INFO: Compiler ID        : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "INFO: Compiler Version   : ${CMAKE_CXX_COMPILER_VERSION}")
if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10.0)
    message(FATAL_ERROR "Require at least gcc-10.0")
endif()
message(STATUS "===================================================================")

# Previous Versions:
#    "v1.20.0 (12-Jan-2022)"
#    "v1.30.0 (09-Jun-2022)" // Add ASN.1 decoding
#    "v1.31.0 (01-Jul-2022)" // Take version number from build system (CMakeLists.txt)
#    "v1.32.0 (19-Aug-2022)" // Re-worked build system.
#    "v1.33.0 (01-Sep-2022)" // Add support for Centos 7.9
#    "v1.34.0 (04-Oct-2022)" // Add CleanseStdVector
#    "v1.34.1 (19-Oct-2022)" // Extend build to also make shared library (qo_decrypt_shared.so). Improve clean to also remove ~/.conan/data/qo_decrypt/. Add test targets: build_like_cli, test_like_cli
#    "v1.34.2 (21-Oct-2022)" // Check compiler version at build-time
#    "v1.34.3 (30-Nov-2022)" // Windows build fixes
project(qo_decrypt VERSION 1.34.3 LANGUAGES C CXX) # Single source of the true project name and version number

include(GNUInstallDirs)

set(CMAKE_POSITION_INDEPENDENT_CODE ON) # Equivalent to adding -fPIC to CMAKE_C_FLAGS/CMAKE_CXX_FLAGS
set(CMAKE_C_STANDARD 99)                # Equivalent to adding -std=c99 to CMAKE_C_FLAGS

option(INTERNAL_BUILD "Create an internal build" OFF)
if(INTERNAL_BUILD)
    add_definitions(-DINTERNAL_BUILD)
endif(INTERNAL_BUILD)

set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Make proect name and version number available as a header file for runtime
set(MY_INCLUDE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/include)
set(MY_PROJECT_CONFIG_H_INPUT_FILENAME ${CMAKE_CURRENT_SOURCE_DIR}/qo_decrypt_project_config.h.in)
set(MY_PROJECT_CONFIG_H_OUTPUT_FILENAME ${MY_INCLUDE_OUTPUT_DIRECTORY}/qo_decrypt/qo_decrypt_project_config.h)
message("--- Create ${MY_PROJECT_CONFIG_H_OUTPUT_FILENAME} for ${CMAKE_PROJECT_NAME} Version ${CMAKE_PROJECT_VERSION}")
configure_file(${MY_PROJECT_CONFIG_H_INPUT_FILENAME} ${MY_PROJECT_CONFIG_H_OUTPUT_FILENAME} @ONLY)

# Make proect name and version number available as a text string for publishing
set(MY_PROJECT_VERSION_TXT_INPUT_FILENAME ${CMAKE_CURRENT_SOURCE_DIR}/qo_decrypt_version.txt.in)
set(MY_PROJECT_VERSION_TXT_OUTPUT_FILENAME ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/qo_decrypt_version.txt)
message("--- Create ${MY_PROJECT_VERSION_TXT_OUTPUT_FILENAME} for ${CMAKE_PROJECT_NAME} Version ${CMAKE_PROJECT_VERSION}")
configure_file(${MY_PROJECT_VERSION_TXT_INPUT_FILENAME} ${MY_PROJECT_VERSION_TXT_OUTPUT_FILENAME} @ONLY)

find_package(MbedTLS CONFIG REQUIRED)
add_subdirectory(../qo_utils qo_utils)

# Debugging
#message(STATUS "INFO: CMAKE_CXX_FLAGS         : ${CMAKE_CXX_FLAGS}")
#message(STATUS "INFO: CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
#message(STATUS "INFO: CMAKE_LIBRARY_PATH      : ${CMAKE_LIBRARY_PATH}")

#if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
#    if(NOT CMAKE_BUILD_PLATFORM STREQUAL "CentOS_7.9.2009")
#        add_link_options(-fsanitize=address)
#    endif()
#endif()

# set(SANITIZER ${CONAN_SETTINGS_COMPILER_SANITIZER})
# if(SANITIZER)
#     if(SANITIZER MATCHES "(Address)")
#     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address" )
#     endif()
# endif()

add_library(qo_decrypt STATIC src/qo_crypto_aes_gcm.c
                              src/qo_cleanse.cpp
                              src/qo_sanitise_files.c
                              src/qo_asn1_decode.cpp
                              src/qo_asn1_encode.cpp)

add_library(qo_decrypt_shared SHARED src/qo_crypto_aes_gcm.c
                              src/qo_cleanse.cpp
                              src/qo_sanitise_files.c
                              src/qo_asn1_decode.cpp
                              src/qo_asn1_encode.cpp)


##################################
# Inputs
##################################
target_link_libraries(qo_decrypt PUBLIC qo_utils PRIVATE MbedTLS::mbedtls)
target_include_directories(qo_decrypt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(qo_decrypt PUBLIC ${MY_INCLUDE_OUTPUT_DIRECTORY})

target_link_libraries(qo_decrypt_shared PUBLIC qo_utils PRIVATE MbedTLS::mbedtls)
target_include_directories(qo_decrypt_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(qo_decrypt_shared PUBLIC ${MY_INCLUDE_OUTPUT_DIRECTORY})

# Lines needed to build QO libs locally are kept as comments in case needed again in future development
#target_link_libraries(qo_decrypt       PRIVATE MbedTLS::mbedtls
#                                               ${CMAKE_CURRENT_SOURCE_DIR}/../IronBridge.Libs.LibQOUtils-c/build/lib/libqo_utils.a)
#target_include_directories(qo_decrypt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../IronBridge.Libs.LibQOUtils-c/include)


##################################
# Outputs
##################################
set_target_properties(qo_decrypt PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set_target_properties(qo_decrypt PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set_target_properties(qo_decrypt PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set_target_properties(qo_decrypt_shared PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set_target_properties(qo_decrypt_shared PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set_target_properties(qo_decrypt_shared PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


##################################
# Tests
##################################
enable_testing()

install(TARGETS qo_decrypt qo_decrypt_shared)
install(DIRECTORY include/qo_decrypt TYPE INCLUDE)
