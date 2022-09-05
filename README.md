# Plugin SDK C++

Status: **Experimental**

Note: *The plugin system is a new feature and is still under active development. You can find more detail in the original [proposal document](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md) and the [official documentation](https://falco.org/docs/plugins/). Since this feature has not yet been released in Falco, consider it as experimental at the moment.*

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


## Usage

The SDK is an header-only library, so the first step is to include the entrypoint header:
```cpp
#include <falcosecurity/sdk.h>
```

Second, The SDK provides building blocks for developing Falcosecurity plugins by using interface-class inherintance. There are pre-built class interfaces for implementing one or more [plugin capabilities](https://falco.org/docs/plugins/#plugins): for instance, `falcosecurity::event_sourcer` for the [event sourcing capability](https://falco.org/docs/plugins/#field-extraction-capability), and `falcosecurity::field_extractor` for the [field extraction capability](https://falco.org/docs/plugins/#field-extraction-capability). Defining a new plugin is a matter of implementing one or more of these capability interfaces. Each interface provides virtual methods to be overridded for defining the behavior of the plugin (some of them are optional with a default implementation).

```cpp
class my_awesome_plugin:
        public falcosecurity::field_extractor,
        public falcosecurity::event_sourcer
{
    const falcosecurity::plugin::information& info() const override;
    bool init(const std::string& config) override;
    ...
}
```

Finally, the third step is to include the pre-built plugin API symbols (only for the implemented capabilities), and provide an implementation for the `falcosecurity::factory()` function that is required by the SDK. These are the only non-interface definitions of the SDK that actually generate code symbols at compilation time, so you need to make sure to include the API headers and defint the `factory()` function in a single `cpp` source file (they don't need to be in the same source file though).

```cpp
// comment-out if not implementing the event sourcing capability
#include <falcosecurity/api/event_sourcing.h>

// comment-out if not implementing the field extraction capability
#include <falcosecurity/api/field_extraction.h>

std::unique_ptr<falcosecurity::plugin> falcosecurity::factory() noexcept
{
    auto p = new my_awesome_plugin();
    return std::unique_ptr<falcosecurity::plugin>(p);
}
```

You're all set! Compile your plugin code with your favorite build system and compiler and feed it to Falco. The only requirement is to compile it as a shared object library. Here's an example with `g++`:
```
g++ -std=c++0x -fPIC -I$(SDK_INCLUDE) -shared -o $(OUTPUT) src/*.cpp
```