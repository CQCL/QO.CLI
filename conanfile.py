import re
from conans import ConanFile, tools
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps


class QoCliConan(ConanFile):
    name = "qo"
    settings = "os", "arch", "compiler", "build_type"

    requires = [
        "boost/[^1.80.0]",
        "cli11/[^2.3.1]",
        "cppcodec/[^0.2]",
        "fmt/[^9.1.0]",
        "gtest/[^1.12.1]",
        "libcurl/7.86.0",
        "magic_enum/[^0.8.2]",
        "openssl/1.1.1s",
        "mbedtls/[^3.1.0]",
        "nlohmann_json/[^3.11.2]",
        "spdlog/[^1.11.0]",
        "yaml-cpp/[^0.7.0]",
    ]

    default_options = {
        "libcurl:with_c_ares": True,
    }
    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "src/*", "test/*"

    def set_version(self):
        git = tools.Git(folder=self.recipe_folder)
        git_tag = git.run("describe --tags")

        match = re.match(
            "^v([0-9]+).([0-9]+).([0-9]+)(-([0-9]+)-g([0-9a-z]+))?$", git_tag
        )

        if match:
            self.version = "%s.%s.%s" % match.group(1, 2, 3)
        else:
            self.version = "0.0.0"

    def generate(self):
        cmake = CMakeToolchain(self, generator="Ninja")
        cmake.generate()

        deps = CMakeDeps(self)
        deps.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
