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

#include "../../sdk.h"

#define CATCH_EXCEPTION(p, block)       \
    try                                 \
    {                                   \
        block;                          \
    }                                   \
    catch (std::exception &e)           \
    {                                   \
        p->m_exception_err = e.what();  \
    }                                   \

namespace falcosecurity::_internal::c
{
    extern "C"
    const char *plugin_get_required_api_version()
    {
        static auto p = falcosecurity::_internal::allocate();
        CATCH_EXCEPTION(p, {
            return p->m_plugin->info().required_api_version.c_str();
        });
        return "";
    }

    extern "C"
    const char *plugin_get_init_schema(ss_plugin_schema_type *schema_type)
    {
        static auto p = falcosecurity::_internal::allocate();
        CATCH_EXCEPTION(p, {
            return p->m_plugin->init_schema(schema_type).c_str();
        });
        return "";
    }

    extern "C"
    const char *plugin_get_name()
    {
        static auto p = falcosecurity::_internal::allocate();
        CATCH_EXCEPTION(p, {
            return p->m_plugin->info().name.c_str();
        });
        return "";
    }

    extern "C"
    const char *plugin_get_description()
    {
        static auto p = falcosecurity::_internal::allocate();
        CATCH_EXCEPTION(p, {
            return p->m_plugin->info().description.c_str();
        });
        return "";
    }

    extern "C"
    const char *plugin_get_contact()
    {
        static auto p = falcosecurity::_internal::allocate();
        CATCH_EXCEPTION(p, {
            return p->m_plugin->info().contact.c_str();
        });
        return "";
    }

    extern "C"
    const char *plugin_get_version()
    {
        static auto p = falcosecurity::_internal::allocate();
        CATCH_EXCEPTION(p, {
            return p->m_plugin->info().version.c_str();
        });
        return "";
    }

    extern "C"
    ss_plugin_t *plugin_init(const char *config, ss_plugin_rc *rc)
    {
        auto p = falcosecurity::_internal::allocate();
        CATCH_EXCEPTION(p, {
            *rc = p->m_plugin->init(std::string(config))
                ? SS_PLUGIN_SUCCESS
                : SS_PLUGIN_FAILURE;
        });
        return (ss_plugin_t*) p;
    }

    extern "C"
    void plugin_destroy(ss_plugin_t *s)
    {
        if (s)
        {
            falcosecurity::_internal::deallocate((falcosecurity::_internal::plugin_wrapper*) s);
        }
    }

    extern "C"
    const char *plugin_get_last_error(ss_plugin_t *s)
    {
        auto p = (falcosecurity::_internal::plugin_wrapper*) s;
        if (!p->m_exception_err.empty())
        {
            return p->m_exception_err.c_str();
        }
        return p->m_plugin->last_error().c_str();
    }
};

#undef CATCH_EXCEPTION