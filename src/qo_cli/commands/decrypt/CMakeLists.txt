add_library(qo_decrypt_command STATIC
        cli.cpp cli.h
        command.cpp command.h
        config.cpp config.h
        key_file.cpp key_file.h
        parameters.cpp parameters.h)

target_link_libraries(qo_decrypt_command PUBLIC CLI11::CLI11 qo_command_shared qo_cli_utils yaml-cpp PRIVATE qo_decrypt  magic_enum::magic_enum)
target_include_directories(qo_decrypt_command PUBLIC ../../..)
