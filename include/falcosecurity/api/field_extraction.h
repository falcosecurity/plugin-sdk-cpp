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

#include "internal/plugin.h"
#include "../internal/deps/nlohmann/json.hpp"

#define CATCH_EXCEPTION_THEN(p, block, then)    \
    try                                         \
    {                                           \
        block;                                  \
    }                                           \
    catch (std::exception &e)                   \
    {                                           \
        p->m_last_err = e.what();               \
        then;                                   \
    }  

#define CATCH_EXCEPTION(p, block)   CATCH_EXCEPTION_THEN(p, block, {})

namespace falcosecurity::_internal::c
{
    extern "C"
    const char* plugin_get_extract_event_sources()
    {
        static std::string res;
        static auto p = falcosecurity::_internal::allocate();
        falcosecurity::_internal::check_field_extractor(p);
        if (res.empty())
        {
            auto arr = nlohmann::json::array();
            for (const auto& s : p->m_extract_event_sources)
            {
                arr.push_back(s);
            }
            res = arr.dump();
        }
        return res.c_str();
    }

    extern "C"
    const char* plugin_get_fields()
    {
        static std::string res;
        static auto p = falcosecurity::_internal::allocate();
        falcosecurity::_internal::check_field_extractor(p);
        if (res.empty())
        {
            auto arr = nlohmann::json::array();
            for (const auto& f : p->m_fields)
            {
                nlohmann::json entry;
                entry["name"] = f.name;
                entry["type"] = falcosecurity::field_extractor::field::type_as_string(f.type);
                entry["isList"] = f.list;
                entry["display"] = f.display;
                entry["desc"] = f.description;
                entry["arg"]["isKey"] = f.arg.key;
                entry["arg"]["isIndex"] = f.arg.index;
                entry["arg"]["isRequired"] = f.arg.required;
                entry["properties"] = nlohmann::json::array();
                for (const auto& p : f.properties)
                {
                    entry["properties"].push_back(p);
                }
                arr.push_back(entry);
            }
            res = arr.dump();
        }
        return res.c_str();
    }

    extern "C"
    ss_plugin_rc plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields)
    {
        auto p = (falcosecurity::_internal::plugin_wrapper*) s;
        falcosecurity::_internal::check_field_extractor(p);
        for (uint32_t i = 0; i < num_fields; i++)
        {
            CATCH_EXCEPTION_THEN(p, {
                if (!p->m_field_extractor->extract(evt, &fields[i]))
                {
                    return SS_PLUGIN_FAILURE;
                }
            }, {
                return SS_PLUGIN_FAILURE;
            });
        }
        return SS_PLUGIN_SUCCESS;
    }
};

#undef CATCH_EXCEPTION_THEN
#undef CATCH_EXCEPTION
