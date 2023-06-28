/*
Copyright (C) 2023 The Falco Authors.

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

#include <falcosecurity/internal/plugin_mixin_async.h>
#include <falcosecurity/internal/plugin_mixin_common.h>
#include <falcosecurity/internal/plugin_mixin_extraction.h>
#include <falcosecurity/internal/plugin_mixin_parsing.h>
#include <falcosecurity/internal/plugin_mixin_sourcing.h>

namespace falcosecurity
{
namespace _internal
{

template<class Plugin>
class plugin_mixin
        : public plugin_mixin_sourcing<
                  Plugin,
                  plugin_mixin_extraction<
                          Plugin,
                          plugin_mixin_parsing<
                                  Plugin, plugin_mixin_async<
                                                  Plugin, plugin_mixin_common<
                                                                  Plugin>>>>>
{
    public:
    plugin_mixin() = default;
    plugin_mixin(plugin_mixin&&) = default;
    plugin_mixin& operator=(plugin_mixin&&) = default;
    plugin_mixin(const plugin_mixin&) = default;
    plugin_mixin& operator=(const plugin_mixin&) = default;
    virtual ~plugin_mixin() = default;
};

}; // namespace _internal
}; // namespace falcosecurity
