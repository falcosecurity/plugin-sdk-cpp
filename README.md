# Plugin SDK C++

[![Falco Ecosystem Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope) [![Sandbox](https://img.shields.io/badge/status-sandbox-red?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#sandbox)

Note: This project is **experimental**.

C++ header only library fo facilitate writing [Falcosecurity plugins](https://falco.org/docs/plugins/). Before using this library, review the [developer's guide](https://falco.org/docs/plugins/developers_guide/) and the [plugin API reference](https://falco.org/docs/plugins/plugin-api-reference/).

The library uses the C++11 standards.


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
