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

class event_writer
{
    public:
    FALCOSECURITY_INLINE
    event_writer() = default;
    FALCOSECURITY_INLINE
    event_writer(event_writer&&) = default;
    FALCOSECURITY_INLINE
    event_writer& operator=(event_writer&&) = default;
    FALCOSECURITY_INLINE
    event_writer(const event_writer& s) = default;
    FALCOSECURITY_INLINE
    event_writer& operator=(const event_writer& s) = default;

    FALCOSECURITY_INLINE
    void grow(size_t size)
    {
        if(m_buf.size() < size)
        {
            m_buf.resize(size);
        }
    }

    FALCOSECURITY_INLINE
    void* get_buf() const { return (void*)m_buf.data(); }

    private:
    std::vector<uint8_t> m_buf;
};

}; // namespace falcosecurity
