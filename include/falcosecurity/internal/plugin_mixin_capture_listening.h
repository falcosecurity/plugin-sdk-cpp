// SPDX-License-Identifier: Apache-2.0
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
#include <falcosecurity/event_reader.h>
#include <falcosecurity/events/decoders.h>
#include <falcosecurity/internal/deps.h>
#include <falcosecurity/types.h>
#include <string>
#include <type_traits>
#include <vector>

namespace falcosecurity
{
namespace _internal
{
template<class Plugin, class Base>
class plugin_mixin_capture_listening : public Base
{
    static_assert(std::has_virtual_destructor<Plugin>::value,
                  "Plugin type must have a virtual destructor");

    public:
    plugin_mixin_capture_listening() = default;
    plugin_mixin_capture_listening(plugin_mixin_capture_listening&&) = default;
    plugin_mixin_capture_listening&
    operator=(plugin_mixin_capture_listening&&) = default;
    plugin_mixin_capture_listening(const plugin_mixin_capture_listening&) =
            default;
    plugin_mixin_capture_listening&
    operator=(const plugin_mixin_capture_listening&) = default;
    virtual ~plugin_mixin_capture_listening() = default;

    FALCOSECURITY_INLINE
    ss_plugin_rc capture_open(const ss_plugin_capture_listen_input* i)
    {
        static_assert(
                std::is_same<bool (Plugin::*)(const capture_listen_input&),
                             decltype(&Plugin::capture_open)>::value,
                "expected signature: bool "
                "capture_open(const capture_listen_input&)");
        FALCOSECURITY_CATCH_ALL(Base::m_last_err_storage, {
            const auto tr = falcosecurity::table_reader(
                    i->table_reader_ext, i->owner, i->get_owner_last_error);
            const auto tw = falcosecurity::table_writer(
                    i->table_writer_ext, i->owner, i->get_owner_last_error);
            capture_listen_input in(i, tr, tw);
            if(!Plugin::capture_open(in))
            {
                return ss_plugin_rc::SS_PLUGIN_FAILURE;
            }
            return ss_plugin_rc::SS_PLUGIN_SUCCESS;
        });
        return ss_plugin_rc::SS_PLUGIN_FAILURE;
    }

    FALCOSECURITY_INLINE
    ss_plugin_rc capture_close(const ss_plugin_capture_listen_input* i)
    {
        static_assert(
                std::is_same<bool (Plugin::*)(const capture_listen_input&),
                             decltype(&Plugin::capture_close)>::value,
                "expected signature: bool "
                "capture_close(const capture_listen_input&)");
        FALCOSECURITY_CATCH_ALL(Base::m_last_err_storage, {
            const auto tr = falcosecurity::table_reader(
                    i->table_reader_ext, i->owner, i->get_owner_last_error);
            const auto tw = falcosecurity::table_writer(
                    i->table_writer_ext, i->owner, i->get_owner_last_error);
            capture_listen_input in(i, tr, tw);
            if(!Plugin::capture_close(in))
            {
                return ss_plugin_rc::SS_PLUGIN_FAILURE;
            }
            return ss_plugin_rc::SS_PLUGIN_SUCCESS;
        });
        return ss_plugin_rc::SS_PLUGIN_FAILURE;
    }
};
}; // namespace _internal
}; // namespace falcosecurity