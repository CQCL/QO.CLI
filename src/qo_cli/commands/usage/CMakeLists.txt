add_library(qo_usage_command STATIC cli.cpp cli.h command.cpp command.h config.cpp config.h parameters.cpp parameters.h)

target_link_libraries(qo_usage_command PUBLIC CLI11::CLI11 qo_command_shared yaml-cpp PRIVATE qo_common qo_cli_utils magic_enum::magic_enum)
target_include_directories(qo_usage_command PUBLIC ../../..)
