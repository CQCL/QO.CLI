find_package(Git)
if(GIT_EXECUTABLE)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --dirty
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_DESCRIBE_OUTPUT
            RESULT_VARIABLE GIT_DESCRIBE_ERROR
            OUTPUT_STRIP_TRAILING_WHITESPACE)

    if(NOT GIT_DESCRIBE_ERROR)
        set(QO_CLI_VERSION ${GIT_DESCRIBE_OUTPUT})
    endif()
endif()

if(NOT DEFINED QO_CLI_VERSION)
    set(QO_CLI_VERSION v0.0.0-unknown)
    message(WARNING "Failed to access Git tags.")
endif()

message(STATUS "Project version: ${QO_CLI_VERSION}")

# Parse the version information into the required parts
string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" QO_CLI_VERSION_MAJOR "${QO_CLI_VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" QO_CLI_VERSION_MINOR "${QO_CLI_VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" QO_CLI_VERSION_PATCH "${QO_CLI_VERSION}")
