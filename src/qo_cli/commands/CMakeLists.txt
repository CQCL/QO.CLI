find_package(CLI11 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

add_subdirectory(shared)

add_library(qo_commands INTERFACE)

target_include_directories(qo_commands INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")

if(INCLUDE_SUPPORT_FOR_KEYGEN)
    add_subdirectory(keygen)
    target_link_libraries(qo_commands INTERFACE qo_keygen_command)
endif(INCLUDE_SUPPORT_FOR_KEYGEN)

if(INCLUDE_SUPPORT_FOR_KEYDECRYPT)
    add_subdirectory(decrypt)
    target_link_libraries(qo_commands INTERFACE qo_decrypt_command)
endif(INCLUDE_SUPPORT_FOR_KEYDECRYPT)

if(INCLUDE_SUPPORT_FOR_ONBOARD)
    add_subdirectory(onboard)
    target_link_libraries(qo_commands INTERFACE qo_onboard_command)
endif(INCLUDE_SUPPORT_FOR_ONBOARD)

if(INCLUDE_SUPPORT_FOR_RANDOMNESS_API)
    add_subdirectory(randomness_api)
    target_link_libraries(qo_commands INTERFACE qo_randomness_api_command)
endif(INCLUDE_SUPPORT_FOR_RANDOMNESS_API )




if(INCLUDE_SUPPORT_FOR_USAGE)
    add_subdirectory(usage)
    target_link_libraries(qo_commands INTERFACE qo_usage_command)
endif(INCLUDE_SUPPORT_FOR_USAGE)
