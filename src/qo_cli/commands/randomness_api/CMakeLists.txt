add_library(qo_randomness_api_command STATIC cli.cpp cli.h command.cpp command.h config.cpp config.h parameters.cpp parameters.h)

target_link_libraries(qo_randomness_api_command PUBLIC CLI11::CLI11 qo_command_shared yaml-cpp PRIVATE qo_common qo_cli_utils magic_enum::magic_enum)
target_include_directories(qo_randomness_api_command PUBLIC ../../..)

if(INCLUDE_SUPPORT_FOR_KEYDECRYPT)
    target_link_libraries(qo_randomness_api_command PUBLIC qo_decrypt_command)
endif(INCLUDE_SUPPORT_FOR_KEYDECRYPT)
