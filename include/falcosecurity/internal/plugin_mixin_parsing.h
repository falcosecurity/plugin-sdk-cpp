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

template<class Plugin, class Base> class plugin_mixin_parsing : public Base
{
    static_assert(std::has_virtual_destructor<Plugin>::value,
                  "Plugin type must have a virtual destructor");

    public:
    plugin_mixin_parsing() = default;
    plugin_mixin_parsing(plugin_mixin_parsing&&) = default;
    plugin_mixin_parsing& operator=(plugin_mixin_parsing&&) = default;
    plugin_mixin_parsing(const plugin_mixin_parsing&) = default;
    plugin_mixin_parsing& operator=(const plugin_mixin_parsing&) = default;
    virtual ~plugin_mixin_parsing() = default;

    std::string m_parse_event_sources_storage;
    std::vector<uint16_t> m_parse_event_types_storage;

    FALCOSECURITY_INLINE
    uint16_t* get_parse_event_types(uint32_t* numtypes) noexcept
    {
        m_parse_event_types_storage.clear();
        for(const auto t : _get_parse_event_types(static_cast<Plugin*>(this)))
        {
            m_parse_event_types_storage.push_back(static_cast<uint16_t>(t));
        }
        *numtypes = (uint32_t)m_parse_event_types_storage.size();
        return m_parse_event_types_storage.data();
    }

    FALCOSECURITY_INLINE
    const char* get_parse_event_sources() noexcept
    {
        auto arr = nlohmann::json::array();
        for(const auto& src :
            _get_parse_event_sources(static_cast<Plugin*>(this)))
        {
            nlohmann::json s = src;
            arr.push_back(s);
        }
        m_parse_event_sources_storage = arr.dump();
        return m_parse_event_sources_storage.c_str();
    }

    FALCOSECURITY_INLINE
    ss_plugin_rc parse_event(const ss_plugin_event_input* evt,
                             const ss_plugin_event_parse_input* in)
    {
        static_assert(std::is_same<bool (Plugin::*)(const parse_event_input&),
                                   decltype(&Plugin::parse_event)>::value,
                      "expected signature: bool "
                      "parse_event(const parse_event_input&)");
        FALCOSECURITY_CATCH_ALL(Base::m_last_err_storage, {
            const auto ev = falcosecurity::event_reader(evt);
            const auto tr = falcosecurity::table_reader(
                    &in->table_reader, in->owner, in->get_owner_last_error);
            const auto tw = falcosecurity::table_writer(
                    &in->table_writer, in->owner, in->get_owner_last_error);
            parse_event_input in(ev, tr, tw);
            if(!Plugin::parse_event(in))
            {
                return ss_plugin_rc::SS_PLUGIN_FAILURE;
            }
            return ss_plugin_rc::SS_PLUGIN_SUCCESS;
        });
        return ss_plugin_rc::SS_PLUGIN_FAILURE;
    }

    private:
    template<typename T>
    FALCOSECURITY_INLINE auto _get_parse_event_sources(T* o)
            -> decltype(o->get_parse_event_sources())
    {
        static_assert(
                std::is_same<std::vector<std::string> (T::*)(),
                             decltype(&T::get_parse_event_sources)>::value,
                "expected signature: std::vector<std::string> "
                "get_parse_event_sources()");
        return o->get_parse_event_sources();
    }

    FALCOSECURITY_INLINE
    auto _get_parse_event_sources(...) -> std::vector<std::string>
    {
        return {};
    }

    template<typename T>
    FALCOSECURITY_INLINE auto _get_parse_event_types(T* o)
            -> decltype(o->get_parse_event_types())
    {
        static_assert(
                std::is_same<std::vector<falcosecurity::event_type> (T::*)(),
                             decltype(&T::get_parse_event_types)>::value,
                "expected signature: std::vector<falcosecurity::event_type> "
                "get_parse_event_types()");
        return o->get_parse_event_types();
    }

    FALCOSECURITY_INLINE
    auto _get_parse_event_types(...) -> std::vector<falcosecurity::event_type>
    {
        return {};
    }
};

}; // namespace _internal
}; // namespace falcosecurity
