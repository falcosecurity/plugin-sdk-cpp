# plugin-sdk-cpp

Status: **Under development**

Note: *The plugin system is a new feature and is still under active development. You can find more detail in the original [proposal document](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md). Since this feature has not yet been released in Falco, consider it as experimental at the moment.*

C++ header only library fo facilitate writing [Falco/Falco libs](https://falco.org/docs/plugins/) plugins.  

Before using this package, review the [developer's guide](https://falco.org/docs/plugins/developers_guide/) which fully documents the API and provides best practices for writing plugins. The developer's guide includes a [walkthrough](https://falco.org/docs/plugins/developers_guide/#c-plugin-sdk-walkthrough).  

When ready to release your plugin, make sure to register the plugin with the Falcosecurity organization by creating a PR to modify the [PLUGINS-REGISTRY.md](https://github.com/falcosecurity/plugins/blob/master/plugins/PLUGINS-REGISTRY.md) file with details on the new plugin. This ensures that a given ID is used by exactly one source plugin, and allows source plugin authors and extractor plugin authors to coordinate about event source formats.


## How to use

You have got 2 choices: either install this library system wide before creating any plugin, or use cmake FetchContent/ExternalProjectAdd like:

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
