add_library(qo_byok_aws_command STATIC cli.cpp cli.h command.cpp command.h config.cpp config.h parameters.cpp parameters.h)

target_link_libraries(qo_byok_aws_command PUBLIC CLI11::CLI11 qo_command_shared yaml-cpp PRIVATE cppcodec::cppcodec qo_cloud_kms::qo_cloud_kms)
