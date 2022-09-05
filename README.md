# Plugin SDK C++

Status: **Experimental**

Note: *The plugin system is a new feature and is still under active development. You can find more detail in the original [proposal document](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md) and the [official documentation](https://falco.org/docs/plugins/). Since this feature has not yet been released in Falco, consider it as experimental at the moment.*

C++ header only library fo facilitate writing [Falcosecurity plugins](https://falco.org/docs/plugins/). Before using this library, review the [developer's guide](https://falco.org/docs/plugins/developers_guide/) and the [plugin API reference](https://falco.org/docs/plugins/plugin-api-reference/).


## How to use

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
