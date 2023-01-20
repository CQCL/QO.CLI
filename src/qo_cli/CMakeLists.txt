# Make project name and version number available as a header file for runtime
set(INCLUDE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/include)
set(QO_CLI_VERSION_H_INPUT_FILENAME ${CMAKE_CURRENT_SOURCE_DIR}/version.h.in)
set(QO_CLI_VERSION_H_OUTPUT_FILENAME ${INCLUDE_OUTPUT_DIRECTORY}/qo_cli/version.h)
configure_file(${QO_CLI_VERSION_H_INPUT_FILENAME} ${QO_CLI_VERSION_H_OUTPUT_FILENAME} @ONLY)

add_library(version_lib INTERFACE
        ${QO_CLI_VERSION_H_OUTPUT_FILENAME})
target_include_directories(version_lib INTERFACE ${INCLUDE_OUTPUT_DIRECTORY})

add_subdirectory(commands)
add_subdirectory(utils)

add_library(qo_app STATIC application.cpp application.h config.cpp config.h parameters.cpp parameters.h)
target_link_libraries(qo_app PUBLIC qo_command_shared PRIVATE qo_commands version_lib)
target_include_directories(qo_app PUBLIC ..)

if(INCLUDE_SUPPORT_FOR_KEYDECRYPT)
    target_link_libraries(qo_app PRIVATE qo_decrypt)
endif(INCLUDE_SUPPORT_FOR_KEYDECRYPT)