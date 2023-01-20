find_package(MbedTLS CONFIG REQUIRED)

add_library(qo_onboard_command STATIC
        cli.cpp cli.h
        command.cpp command.h
        config.cpp config.h
        onboard.cpp onboard.h
        parameters.cpp parameters.h)

target_link_libraries(qo_onboard_command PUBLIC CLI11::CLI11 qo_command_shared yaml-cpp PRIVATE MbedTLS::mbedtls qo_common)
target_include_directories(qo_onboard_command PUBLIC ../../..)
