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

#define FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(__t)                             \
    namespace falcosecurity                                                    \
    {                                                                          \
    namespace _internal                                                        \
    {                                                                          \
                                                                               \
    static plugin_mixin<__t> s_plugin_extraction;                              \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    uint16_t* plugin_get_extract_event_types(uint32_t* numtypes)               \
    {                                                                          \
        return s_plugin_extraction.get_extract_event_types(numtypes);          \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_extract_event_sources()                             \
    {                                                                          \
        return s_plugin_extraction.get_extract_event_sources();                \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    const char* plugin_get_fields()                                            \
    {                                                                          \
        return s_plugin_extraction.get_fields();                               \
    }                                                                          \
                                                                               \
    FALCOSECURITY_EXPORT                                                       \
    ss_plugin_rc                                                               \
    plugin_extract_fields(ss_plugin_t* s, const ss_plugin_event_input* evt,    \
                          const ss_plugin_field_extract_input* in)             \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->extract_fields(evt, in);                                     \
    }                                                                          \
    }; /* _internal */                                                         \
    }; /* falcosecurity */
