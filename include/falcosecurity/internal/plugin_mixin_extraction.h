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
#include <falcosecurity/extract_request.h>
#include <falcosecurity/internal/deps.h>
#include <falcosecurity/types.h>
#include <string>
#include <type_traits>
#include <vector>

namespace falcosecurity
{
namespace _internal
{

template<class Plugin, class Base> class plugin_mixin_extraction : public Base
{
    static_assert(std::has_virtual_destructor<Plugin>::value,
                  "Plugin type must have a virtual destructor");

    public:
    plugin_mixin_extraction() = default;
    plugin_mixin_extraction(plugin_mixin_extraction&&) = default;
    plugin_mixin_extraction& operator=(plugin_mixin_extraction&&) = default;
    plugin_mixin_extraction(const plugin_mixin_extraction&) = default;
    plugin_mixin_extraction&
    operator=(const plugin_mixin_extraction&) = default;
    virtual ~plugin_mixin_extraction() = default;

    std::string m_fields_storage;
    std::string m_extract_event_sources_storage;
    std::vector<uint16_t> m_extract_event_types_storage;
    std::vector<falcosecurity::extract_request> m_extract_requests;

    FALCOSECURITY_INLINE
    uint16_t* get_extract_event_types(uint32_t* numtypes) noexcept
    {
        m_extract_event_types_storage.clear();
        for(const auto& t :
            _get_extract_event_types(static_cast<Plugin*>(this)))
        {
            m_extract_event_types_storage.push_back(static_cast<uint16_t>(t));
        }
        *numtypes = (uint32_t)m_extract_event_types_storage.size();
        return m_extract_event_types_storage.data();
    }

    FALCOSECURITY_INLINE
    const char* get_extract_event_sources() noexcept
    {
        auto arr = nlohmann::json::array();
        for(const auto& src :
            _get_extract_event_sources(static_cast<Plugin*>(this)))
        {
            nlohmann::json s = src;
            arr.push_back(s);
        }
        m_extract_event_sources_storage = arr.dump();
        return m_extract_event_sources_storage.c_str();
    }

    FALCOSECURITY_INLINE
    const char* get_fields() noexcept
    {
        static_assert(
                std::is_same<std::vector<falcosecurity::field_info> (
                                     Plugin::*)(),
                             decltype(&Plugin::get_fields)>::value,
                "expected signature: std::vector<falcosecurity::field_info> "
                "get_fields()");
        auto fields = Plugin::get_fields();
        auto arr = nlohmann::json::array();
        for(const auto& f : fields)
        {
            nlohmann::json entry;
            entry["name"] = f.name;
            entry["type"] = falcosecurity::to_string(f.type);
            entry["isList"] = f.list;
            entry["display"] = f.display;
            entry["desc"] = f.description;
            entry["arg"]["isKey"] = f.arg.key;
            entry["arg"]["isIndex"] = f.arg.index;
            entry["arg"]["isRequired"] = f.arg.required;
            entry["properties"] = nlohmann::json::array();
            for(const auto& p : f.properties)
            {
                entry["properties"].push_back(p);
            }
            arr.push_back(entry);
        }
        m_fields_storage = arr.dump();
        return m_fields_storage.c_str();
    }

    ss_plugin_rc extract_fields(const ss_plugin_event_input* evt,
                                const ss_plugin_field_extract_input* in)
    {
        static_assert(
                std::is_same<bool (Plugin::*)(const extract_fields_input&),
                             decltype(&Plugin::extract)>::value,
                "expected signature: bool extract(const "
                "falcosecurity::extract_fields_input&)");
        FALCOSECURITY_CATCH_ALL(Base::m_last_err_storage, {
            const auto ev = falcosecurity::event_reader(evt);
            const auto tr = falcosecurity::table_reader(
                    &in->table_reader, in->owner, in->get_owner_last_error);
            extract_fields_input input(ev, tr);
            if(m_extract_requests.size() < in->num_fields)
            {
                m_extract_requests.resize(in->num_fields);
            }
            for(uint32_t i = 0; i < in->num_fields; i++)
            {
                auto& req = m_extract_requests[i];
                req.set_request(in->fields + i);
                input.set_extract_request(req);
                if(!Plugin::extract(input))
                {
                    return ss_plugin_rc::SS_PLUGIN_FAILURE;
                }
            }
            return ss_plugin_rc::SS_PLUGIN_SUCCESS;
        });
        return ss_plugin_rc::SS_PLUGIN_FAILURE;
    }

    private:
    template<typename T>
    FALCOSECURITY_INLINE auto _get_extract_event_sources(T* o)
            -> decltype(o->get_extract_event_sources())
    {
        static_assert(
                std::is_same<std::vector<std::string> (T::*)(),
                             decltype(&T::get_extract_event_sources)>::value,
                "expected signature: std::vector<std::string> "
                "get_extract_event_sources()");
        return o->get_extract_event_sources();
    }

    FALCOSECURITY_INLINE
    auto _get_extract_event_sources(...) -> std::vector<std::string>
    {
        return {};
    }

    template<typename T>
    FALCOSECURITY_INLINE auto _get_extract_event_types(T* o)
            -> decltype(o->get_extract_event_types())
    {
        static_assert(
                std::is_same<std::vector<falcosecurity::event_type> (T::*)(),
                             decltype(&T::get_extract_event_types)>::value,
                "expected signature: std::vector<falcosecurity::event_type> "
                "get_extract_event_types()");
        return o->get_extract_event_types();
    }

    FALCOSECURITY_INLINE
    auto _get_extract_event_types(...) -> std::vector<falcosecurity::event_type>
    {
        return {};
    }
};

}; // namespace _internal
}; // namespace falcosecurity
