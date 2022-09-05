/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include <memory>
#include "plugin.h"

namespace falcosecurity
{
    /**
     * @brief Creates and returns a new plugin implementing the
     * falcosecurity::plugin class interface. This function is used by the SDK
     * when creating a new plugin. The newly created plugin can also implement
     * one or more plugin capability class interfaces.
     * 
     * The SDK only provides a declaration of this function and SDK users
     * are responsible for providing its definition. This is used to instruct
     * the SDK about the user-defined plugin and the right way to initialize it.
     * 
     * This function must be idempotent, as the SDK will invoke arbitrarily.
     * 
     * @return std::unique_ptr<plugin> representing the newly-created plugin
     */
    extern std::unique_ptr<plugin> factory() noexcept;
}
