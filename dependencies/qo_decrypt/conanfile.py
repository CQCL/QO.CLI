from conans import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps

class QoDecryptConan(ConanFile):
    name = "qo_decrypt"
    version = "1.34.3"
    url = "https://github.com/CQCL-DEV/IronBridge.Libs.LibQODecrypt-c.git"
    description = "Quantum Origin Client-side Decryption Library"

    # NOTE: It seems that multiple requires statements are not supported. Keep everything in a single requires clause.
    requires = "mbedtls/[>=3.0.0]", "qo_utils/1.3.2@quantinuum/main", "gtest/1.12.1"
    #requires = "mbedtls/[>=3.0.0]", "qo_utils/1.3.0@quantinuum/local_builds", "gtest/1.11.0"

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"

    options         = { "shared"        : [True, False],  # Build a shared library
                        "fPIC"          : [True, False],  # Generate position-independent code
                        "internal"      : [True, False],  # Create an internal build
                      }
    default_options = { "shared"        : False,
                        "fPIC"          : True,
                        "internal"      : False,
                        "mbedtls:shared": False
                      }

    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "qo_decrypt_project_config.h.in", "qo_decrypt_version.txt.in", "include/*", "src/*", "test/*"

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
        self.cpp_info.libs = ["qo_decrypt"]
