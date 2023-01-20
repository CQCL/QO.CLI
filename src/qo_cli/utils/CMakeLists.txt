add_library(qo_cli_utils STATIC
        key_writer.cpp key_writer.h
        utils.cpp utils.h)
target_link_libraries(qo_cli_utils PRIVATE qo_command_shared qo_decrypt  fmt::fmt spdlog::spdlog)
target_include_directories(qo_cli_utils PUBLIC .)



    target_link_libraries(qo_cli_utils PUBLIC qo_common)
