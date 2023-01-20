from conans import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps

class QoUtilsConan(ConanFile):
    name = "qo_utils"
    version = "1.3.2"
    url = "https://github.com/CQCL-DEV/IronBridge.Libs.LibQOUtils-c.git"
    description = "Quantum Origin Client-side Utility Library"

    # NOTE: It seems that multiple requires statements are not supported. Keep everything in a single requires clause.
    #requires = "gtest/1.11.0"

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"

    options         = { "shared"        : [True, False],  # Build a shared library
                        "fPIC"          : [True, False],  # Generate position-independent code
                        "internal"      : [True, False],  # Create an internal build
                      }
    default_options = { "shared"        : False,
                        "fPIC"          : True,
                        "internal"      : False
                      }

    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "qo_utils_project_config.h.in", "qo_utils_version.txt.in", "include/*", "src/*", "test/*"

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["INTERNAL_BUILD"] = self.options.internal
        tc.generate()

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
        self.cpp_info.libs = ["qo_utils"]
