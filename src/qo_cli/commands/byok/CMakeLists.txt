add_library(qo_byok_command STATIC cli.cpp cli.h command.cpp command.h config.cpp config.h parameters.cpp parameters.h)

target_link_libraries(qo_byok_command PUBLIC CLI11::CLI11 qo_command_shared yaml-cpp PRIVATE magic_enum::magic_enum)
target_include_directories(qo_byok_command PUBLIC ../../..)

add_subdirectory(aws)
add_subdirectory(az)

target_link_libraries(qo_byok_command PUBLIC qo_byok_aws_command qo_byok_az_command)
