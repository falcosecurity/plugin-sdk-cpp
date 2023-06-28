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

#define FALCOSECURITY_PLUGIN_ASYNC_EVENTS(__t)                                 \
    namespace falcosecurity                                                    \
    {                                                                          \
    namespace _internal                                                        \
    {                                                                          \
                                                                               \
    static plugin_mixin<__t> s_plugin_async;                                   \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_async_events()                                      \
    {                                                                          \
        return s_plugin_async.get_async_events();                              \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_async_event_sources()                               \
    {                                                                          \
        return s_plugin_async.get_async_event_sources();                       \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    ss_plugin_rc                                                               \
    plugin_set_async_event_handler(ss_plugin_t* s, ss_plugin_owner_t* o,       \
                                   const ss_plugin_async_event_handler_t h)    \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->set_async_event_handler(o, h);                               \
    }                                                                          \
    }; /* _internal */                                                         \
    }; /* falcosecurity */
