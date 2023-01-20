cmake_minimum_required(VERSION 3.20)

project(qo_common VERSION 0.9 LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(cppcodec CONFIG REQUIRED)
find_package(CURL CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(magic_enum CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_link_options(-fsanitize=address)
endif()

add_library(qo_common
        src/exceptions.cpp
        src/key_request.cpp
        src/key_response.cpp
        src/onboard_request.cpp
        src/onboard_response.cpp
        src/parameters.cpp
        src/randomness_request.cpp
        src/randomness_response.cpp
        src/request.cpp
        src/service.cpp
        src/usage_request.cpp
        src/usage_response.cpp
        src/utils.cpp)
target_link_libraries(qo_common
        PUBLIC CURL::libcurl nlohmann_json::nlohmann_json
        PRIVATE cppcodec::cppcodec fmt::fmt magic_enum::magic_enum spdlog::spdlog)
target_include_directories(qo_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)


install(TARGETS qo_common)
install(DIRECTORY include/qo_common
        TYPE INCLUDE)
