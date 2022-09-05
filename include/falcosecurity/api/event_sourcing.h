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
        p->m_exception_err = e.what();          \
        then;                                   \
    }  

#define CATCH_EXCEPTION(p, block)   CATCH_EXCEPTION_THEN(p, block, {})

namespace falcosecurity::_internal::c
{
    extern "C"
    uint32_t plugin_get_id()
    {
        static auto p = falcosecurity::_internal::allocate();
        falcosecurity::_internal::check_event_sourcer(p);
        CATCH_EXCEPTION(p, {
            return p->m_event_sourcer->id();
        });
        return 0;
    }

    extern "C"
    const char* plugin_get_event_source()
    {
        static auto p = falcosecurity::_internal::allocate();
        falcosecurity::_internal::check_event_sourcer(p);
        CATCH_EXCEPTION(p, {
            return p->m_event_sourcer->event_source().c_str();
        });
        return "";
    }

    extern "C"
    const char* plugin_event_to_string(ss_plugin_t *s, const ss_plugin_event *evt)
    {
        auto p = (falcosecurity::_internal::plugin_wrapper*) s;
        falcosecurity::_internal::check_event_sourcer(p);
        CATCH_EXCEPTION(p, {
            return p->m_event_sourcer->event_as_string(evt).c_str();
        });
        return "";
    }

    extern "C"
    const char* plugin_list_open_params(ss_plugin_t* s, ss_plugin_rc* rc)
    {
        auto p = (falcosecurity::_internal::plugin_wrapper*) s;
        falcosecurity::_internal::check_event_sourcer(p);

        CATCH_EXCEPTION_THEN(p, {
            if (!p->m_event_sourcer->open_param_list(p->m_open_param_list))
            {
                *rc = SS_PLUGIN_FAILURE;
                return NULL;
            }
        }, {
            *rc = SS_PLUGIN_FAILURE;
            return NULL;
        });

        *rc = SS_PLUGIN_SUCCESS;
        auto arr = nlohmann::json::array();
        for (const auto& param : p->m_open_param_list)
        {
            nlohmann::json entry;
            entry["value"] = param.value;
            if (!param.description.empty())
            {
                entry["desc"] = param.description;
            }
            if (!param.separator.empty())
            {
                entry["separator"] = param.separator;
            }
            arr.push_back(entry);
        }
        p->m_open_param_list_str = arr.dump();
        *rc = SS_PLUGIN_SUCCESS;
        return p->m_open_param_list_str.c_str();
    }

    extern "C"
    ss_instance_t* plugin_open(ss_plugin_t* s, const char* params, ss_plugin_rc* rc)
    {
        auto p = (falcosecurity::_internal::plugin_wrapper*) s;
        falcosecurity::_internal::check_event_sourcer(p);
        auto res = new falcosecurity::_internal::instance_wrapper();

        CATCH_EXCEPTION_THEN(p, {
            res->instance = p->m_event_sourcer->open(params);
            if (!res)
            {
                *rc = SS_PLUGIN_FAILURE;
                return NULL;
            }
            *rc = SS_PLUGIN_SUCCESS;
        }, {
            *rc = SS_PLUGIN_FAILURE;
            return NULL;
        });
        return res;
    }

    extern "C"
    void plugin_close(ss_plugin_t* s, ss_instance_t* h)
    {
        if (h)
        {
            auto p = (falcosecurity::_internal::plugin_wrapper*) s;
            falcosecurity::_internal::check_event_sourcer(p);
            auto i = (falcosecurity::_internal::instance_wrapper*) h;
            delete i;
        }
    }

    extern "C"
    const char* plugin_get_progress(ss_plugin_t* s, ss_instance_t* h, uint32_t* progress_pct)
    {
        auto p = (falcosecurity::_internal::plugin_wrapper*) s;
        falcosecurity::_internal::check_event_sourcer(p);
        auto i = (falcosecurity::_internal::instance_wrapper*) h;

        CATCH_EXCEPTION(p, {
            double pct = 0.0;
            auto str = i->instance->get_progress(p->m_event_sourcer, &pct).c_str();
            *progress_pct = (uint32_t)(pct * 10000);
            return str;
        });

        *progress_pct = 0;
        return "";
    }

    extern "C"
    ss_plugin_rc plugin_next_batch(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event **evts)
    {
        auto p = (falcosecurity::_internal::plugin_wrapper*) s;
        falcosecurity::_internal::check_event_sourcer(p);
        auto i = (falcosecurity::_internal::instance_wrapper*) h;

        CATCH_EXCEPTION_THEN(p, {
            i->m_event.ts = UINT64_MAX;
            ss_plugin_rc rc = i->instance->next(p->m_event_sourcer, &i->m_event);
            if (rc == SS_PLUGIN_SUCCESS)
            {
                *nevts = 1;
                *evts = &i->m_event;
            }
            else
            {
                *nevts = 0;
                *evts = NULL;
            }
            return rc;
        }, {
            *nevts = 0;
            *evts = NULL;
            return SS_PLUGIN_FAILURE;
        });
    }
};

#undef CATCH_EXCEPTION_THEN
#undef CATCH_EXCEPTION
