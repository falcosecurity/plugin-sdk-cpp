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

#define FALCOSECURITY_PLUGIN_EVENT_SOURCING(__t, __i)                          \
    namespace falcosecurity                                                    \
    {                                                                          \
    namespace _internal                                                        \
    {                                                                          \
                                                                               \
    static plugin_mixin<__t> s_plugin_sourcing;                                \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    uint32_t plugin_get_id() { return s_plugin_sourcing.get_id(); }            \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_event_source()                                      \
    {                                                                          \
        return s_plugin_sourcing.get_event_source();                           \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_list_open_params(ss_plugin_t* s, ss_plugin_rc* rc)      \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->list_open_params(rc);                                        \
    }                                                                          \
                                                                               \
    const char* plugin_event_to_string(ss_plugin_t* s,                         \
                                       const ss_plugin_event_input* evt)       \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->event_to_string(evt);                                        \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    ss_instance_t* plugin_open(ss_plugin_t* s, const char* params,             \
                               ss_plugin_rc* rc)                               \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->open<__i>(params, rc);                                       \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    void plugin_close(ss_plugin_t* s, ss_instance_t* h)                        \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->close<__i>(h);                                               \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_progress(ss_plugin_t* s, ss_instance_t* h,          \
                                    uint32_t* progress_pct)                    \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->get_progress<__i>(h, progress_pct);                          \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    ss_plugin_rc plugin_next_batch(ss_plugin_t* s, ss_instance_t* h,           \
                                   uint32_t* nevts, ss_plugin_event*** evts)   \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->next_batch<__i>(h, nevts, evts);                             \
    }                                                                          \
                                                                               \
    }; /* _internal */                                                         \
    }; /* falcosecurity */
