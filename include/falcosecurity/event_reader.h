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

#include <falcosecurity/internal/hacks.h>
#include <falcosecurity/types.h>
#include <stdexcept>
#include <string>

namespace falcosecurity
{

class event_reader
{
    public:
    FALCOSECURITY_INLINE
    event_reader(const _internal::ss_plugin_event_input* i): m_input(i) {}
    FALCOSECURITY_INLINE
    event_reader(event_reader&&) = default;
    FALCOSECURITY_INLINE
    event_reader& operator=(event_reader&&) = default;
    FALCOSECURITY_INLINE
    event_reader(const event_reader&) = default;
    FALCOSECURITY_INLINE
    event_reader& operator=(const event_reader&) = default;

    FALCOSECURITY_INLINE
    void* get_buf() const { return (void*)m_input->evt; }

    FALCOSECURITY_INLINE
    event_type get_type() const
    {
        return static_cast<event_type>(m_input->evt->type);
    }

    FALCOSECURITY_INLINE
    uint64_t get_ts() const { return m_input->evt->ts; }

    FALCOSECURITY_INLINE
    uint64_t get_tid() const { return m_input->evt->tid; }

    FALCOSECURITY_INLINE
    uint64_t get_num() const { return m_input->evtnum; }

    FALCOSECURITY_INLINE
    const char* get_source() const { return m_input->evtsrc; }

    private:
    const _internal::ss_plugin_event_input* m_input;
};

}; // namespace falcosecurity
