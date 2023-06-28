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

#include <falcosecurity/internal/plugin_mixin.h>

#define FALCOSECURITY_PLUGIN(__t)                                              \
    namespace falcosecurity                                                    \
    {                                                                          \
    namespace _internal                                                        \
    {                                                                          \
                                                                               \
    static plugin_mixin<__t> s_plugin_common;                                  \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_required_api_version()                              \
    {                                                                          \
        return s_plugin_common.get_required_api_version();                     \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_version() { return s_plugin_common.get_version(); } \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_name() { return s_plugin_common.get_name(); }       \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_description()                                       \
    {                                                                          \
        return s_plugin_common.get_description();                              \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_contact() { return s_plugin_common.get_contact(); } \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_init_schema(ss_plugin_schema_type* st)              \
    {                                                                          \
        return s_plugin_common.get_init_schema(st);                            \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_last_error(ss_plugin_t* s)                          \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->get_last_error();                                            \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    ss_plugin_t* plugin_init(const ss_plugin_init_input* input,                \
                             ss_plugin_rc* rc)                                 \
    {                                                                          \
        auto res = new plugin_mixin<__t>();                                    \
        *rc = res->init(input);                                                \
        return static_cast<ss_plugin_t*>(res);                                 \
    }                                                                          \
                                                                               \
    /* todo(jasondellaluce): should we have an explicit "destroy" function for \
     * catching errors? */                                                     \
    FALCOSECURITY_EXPORT                                                       \
    void plugin_destroy(ss_plugin_t* s)                                        \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        delete p;                                                              \
    }                                                                          \
    }; /* _internal */                                                         \
    }; /* falcosecurity */
