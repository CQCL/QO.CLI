find_package(spdlog CONFIG REQUIRED)

add_subdirectory(qo_cli)

# Set the source files. This will need to be updated for new services, or structure changed to support wildcards.
set(PROJECT_SOURCE_FILES
        main.cpp)

add_executable(qo ${PROJECT_SOURCE_FILES})
target_link_libraries(qo PRIVATE qo_app version_lib qo_commands spdlog::spdlog)

# Install binary
install(TARGETS qo
        RUNTIME DESTINATION bin)
