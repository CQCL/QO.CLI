
cmake_minimum_required(VERSION 3.17)

#CMake Error at CMakeLists.txt:4 (project):
#  VERSION not allowed unless CMP0048 is set to NEW
if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()

# Previous Versions:
#    "v1.0.1
#    "v1.2.0 (29-Jul-2022)// Take version number from build system (CMakeLists.txt)
#    "v1.3.0 (19-Aug-2022)" // Unified build for Centos and Ubuntu. Re-worked build system.
#    "v1.3.1 (10-Oct-2022)" // Fix asan on Centos build
#    "v1.3.2 (30-Nov-2022)" // Fixes for Windows builds
project(qo_utils VERSION 1.3.2 LANGUAGES C CXX) # Single source of the true project name and version number

include(GNUInstallDirs)

set(CMAKE_POSITION_INDEPENDENT_CODE ON) # Equivalent to adding -fPIC to CMAKE_C_FLAGS/CMAKE_CXX_FLAGS
set(CMAKE_C_STANDARD 99)                # Equivalent to adding -std=c99 to CMAKE_C_FLAGS

if(CMAKE_BUILD_PLATFORM STREQUAL "Ubuntu_20.04")
    message(STATUS "INFO: Builing for Ubuntu 20.04 (${CMAKE_BUILD_PLATFORM})")
elseif(CMAKE_BUILD_PLATFORM STREQUAL "CentOS_7.9.2009")
    message(STATUS "INFO: Builing for Centos 7 (${CMAKE_BUILD_PLATFORM})")
elseif(CMAKE_BUILD_PLATFORM STREQUAL "Win32")
    message(STATUS "INFO: Building for Windows (${CMAKE_BUILD_PLATFORM})")
else()
    message(STATUS "INFO: Building for Unknown platform (${CMAKE_BUILD_PLATFORM})")
endif()

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
set(MY_PROJECT_CONFIG_H_INPUT_FILENAME ${CMAKE_CURRENT_SOURCE_DIR}/qo_utils_project_config.h.in)
set(MY_PROJECT_CONFIG_H_OUTPUT_FILENAME ${MY_INCLUDE_OUTPUT_DIRECTORY}/qo_utils/qo_utils_project_config.h)
message("--- Create ${MY_PROJECT_CONFIG_H_OUTPUT_FILENAME} for ${CMAKE_PROJECT_NAME} Version ${CMAKE_PROJECT_VERSION}")
configure_file(${MY_PROJECT_CONFIG_H_INPUT_FILENAME} ${MY_PROJECT_CONFIG_H_OUTPUT_FILENAME} @ONLY)
include_directories(${MY_INCLUDE_OUTPUT_DIRECTORY}) # This allows the 'qo_utils_project_config.h' file to be used throughout the program

# Make proect name and version number available as a text string for publishing
set(MY_PROJECT_VERSION_TXT_INPUT_FILENAME ${CMAKE_CURRENT_SOURCE_DIR}/qo_utils_version.txt.in)
set(MY_PROJECT_VERSION_TXT_OUTPUT_FILENAME ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/qo_utils_version.txt)
message("--- Create ${MY_PROJECT_VERSION_TXT_OUTPUT_FILENAME} for ${CMAKE_PROJECT_NAME} Version ${CMAKE_PROJECT_VERSION}")
configure_file(${MY_PROJECT_VERSION_TXT_INPUT_FILENAME} ${MY_PROJECT_VERSION_TXT_OUTPUT_FILENAME} @ONLY)

# Debugging
#message(STATUS "INFO: CMAKE_CXX_FLAGS         : ${CMAKE_CXX_FLAGS}")
#message(STATUS "INFO: CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
#message(STATUS "INFO: CMAKE_LIBRARY_PATH      : ${CMAKE_LIBRARY_PATH}")

#if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
#    if(NOT CMAKE_BUILD_PLATFORM STREQUAL "CentOS_7.9.2009")
#        add_link_options(-fsanitize=address)
#    endif()
#endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
    message(STATUS "INFO: Use statically linked address sanitizer (libasan)")
    add_link_options(-fsanitize=address)
    add_link_options(-static-libasan)
endif()

# set(SANITIZER ${CONAN_SETTINGS_COMPILER_SANITIZER})
# if(SANITIZER)
#     if(SANITIZER MATCHES "(Address)")
#     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address" )
#     endif()
# endif()

add_library(qo_utils STATIC src/qo_base64.c
                            src/qo_config.c
                            src/qo_filelock.c
                            src/qo_json.c
                            src/qo_logging.c
                            src/qo_string.c)
add_library(qo_utils_shared SHARED src/qo_base64.c
                            src/qo_config.c
                            src/qo_filelock.c
                            src/qo_json.c
                            src/qo_logging.c
                            src/qo_string.c)


##################################
# Inputs
##################################
target_include_directories(qo_utils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(qo_utils_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)


##################################
# Outputs
##################################
set_target_properties(qo_utils PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set_target_properties(qo_utils PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set_target_properties(qo_utils PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set_target_properties(qo_utils_shared PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set_target_properties(qo_utils_shared PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set_target_properties(qo_utils_shared PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


##################################
# Tests
##################################
enable_testing()

install(TARGETS qo_utils qo_utils_shared)
install(DIRECTORY include/qo_utils TYPE INCLUDE)
