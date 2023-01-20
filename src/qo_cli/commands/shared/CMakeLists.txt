find_package(Boost CONFIG REQUIRED)

add_library(qo_command_shared STATIC
        api_parameters.cpp api_parameters.h
        command_base.cpp command_base.hpp
        decryption_parameters.cpp decryption_parameters.h
        key_parameters.cpp key_parameters.h
         
         
        parameter_base.cpp parameter_base.h
        shared_config.cpp shared_config.h)

target_include_directories(qo_command_shared PUBLIC .)
target_link_libraries(qo_command_shared
        PUBLIC
            qo_commands qo_common Boost::boost CLI11::CLI11 cppcodec::cppcodec fmt::fmt magic_enum::magic_enum spdlog::spdlog yaml-cpp qo_cli_utils 
        PRIVATE
            qo_decrypt)

if(INCLUDE_SUPPORT_FOR_KEYDECRYPT)
    target_sources(qo_command_shared PRIVATE decrypt.h decrypt.cpp)
endif(INCLUDE_SUPPORT_FOR_KEYDECRYPT)


