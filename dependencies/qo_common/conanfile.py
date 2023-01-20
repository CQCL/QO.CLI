from conans import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps

class QoCommonConan(ConanFile):
    name = "qo_common"
    version = "0.9"
    url = "https://github.com/CQCL-DEV/IronBridge.Libs.QO-Common.git"
    description = "Common client-side code"
    requires = "cppcodec/[^0.2]", "fmt/[^9.1.0]", "gtest/[^1.12.1]", "libcurl/[^7.86.0]", "magic_enum/[^0.8.2]", "nlohmann_json/[^3.11.2]", "spdlog/[^1.11.0]"

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True, "libcurl:with_c_ares": True, "libcurl:with_threaded_resolver": False}

    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "include/*", "src/*", "test/*"

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

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

    def package_info(self):
        self.cpp_info.libs = ["qo_common"]
