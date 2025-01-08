# Plugin SDK C++

[![Falco Ecosystem Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope) [![Sandbox](https://img.shields.io/badge/status-sandbox-red?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#sandbox)

Note: This project is **experimental**.

C++ header only library fo facilitate writing [Falcosecurity plugins](https://falco.org/docs/plugins/). Before using this library, review the [developer's guide](https://falco.org/docs/plugins/developers_guide/) and the [plugin API reference](https://falco.org/docs/plugins/plugin-api-reference/).

The library uses the C++11 standards.

> __NOTE:__ master is not guaranteed to be compatible with latest released Falco; use correct release instead to target a specific Falco version!

## Installation

You have got 2 choices: either install this library system wide before creating any plugin, include the library files manually, or use cmake FetchContent/ExternalProjectAdd like:

```
project(your_proj VERSION 1.0.0 LANGUAGES CXX)

set(YOUR_SRCS ...) # set the srcs for your plugin
add_library(${PROJECT_NAME} SHARED ${YOUR_SRCS})

#### Fetch plugin-sdk-cpp and link it to your target
include(FetchContent)
FetchContent_Declare(
  plugin-sdk-cpp
  GIT_REPOSITORY https://github.com/falcosecurity/plugin-sdk-cpp.git
  GIT_TAG        703bd9caab50b139428cea1aaff9974ebee5742e # desired git tag here
)
FetchContent_MakeAvailable(plugin-sdk-cpp)

target_link_library(${PROJECT_NAME} plugin-sdk-cpp)
####
```

### Code formatting

The code style convention of this repository can be found in [clang-format](https://clang.llvm.org/docs/ClangFormat.html).

The chosen `clang-format` version is `15`, which can be installed alongside the LLVM toolchain or as stand-alone through package managers (e.g. `apt install clang-format-15`).

It can also be found at:
- https://github.com/llvm/llvm-project/releases/tag/llvmorg-15.0.7
- https://github.com/ssciwr/clang-format-wheel/releases/tag/v15.0.7

Most advanced editors and IDE can detect the `.clang-format` and let you format while working. Alternatively, you can run `clang-format` command manually as follows:

```
find . -iname *.h -o -iname *.cpp \
    | grep -v "internal/deps/" \
    | xargs clang-format-15 -i
```

