add_library(qo_byok_az_command STATIC cli.cpp cli.h command.cpp command.h config.cpp config.h parameters.cpp parameters.h)

target_link_libraries(qo_byok_az_command PUBLIC CLI11::CLI11 qo_command_shared yaml-cpp qo_cli_utils PRIVATE qo_decrypt cppcodec::cppcodec qo_common magic_enum::magic_enum)
