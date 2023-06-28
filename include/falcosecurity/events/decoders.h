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
#include <falcosecurity/internal/hacks.h>
#include <falcosecurity/types.h>
#include <stdexcept>
#include <string>

namespace falcosecurity
{
namespace events
{

// todo(jasondellaluce): autogenerate these for every event type

// todo(jasondellaluce): have all event codes somewhere

class pluginevent_e_decoder
{
    public:
    FALCOSECURITY_INLINE
    pluginevent_e_decoder(const falcosecurity::event_reader& r)
    {
        if(r.get_type() != 322)
        {
            throw std::invalid_argument("invalid event type conversion in "
                                        "event decoder: requested=" +
                                        std::to_string(322) + ", actual=" +
                                        std::to_string(r.get_type()));
        }

        uint8_t* parambuf = ((uint8_t*)r.get_buf() + 26);
        parambuf += sizeof(uint32_t);
        m_datalen = *(uint32_t*)parambuf;

        parambuf += sizeof(uint32_t);
        m_plugin_id = *(uint32_t*)parambuf;
        parambuf += sizeof(uint32_t);
        m_data = (void*)parambuf;
    }
    FALCOSECURITY_INLINE
    pluginevent_e_decoder(pluginevent_e_decoder&&) = default;
    FALCOSECURITY_INLINE
    pluginevent_e_decoder& operator=(pluginevent_e_decoder&&) = delete;
    FALCOSECURITY_INLINE
    pluginevent_e_decoder(const pluginevent_e_decoder&) = default;
    FALCOSECURITY_INLINE
    pluginevent_e_decoder& operator=(const pluginevent_e_decoder&) = delete;

    FALCOSECURITY_INLINE
    uint32_t get_plugin_id() const { return m_plugin_id; }

    FALCOSECURITY_INLINE
    void* get_data(uint32_t* len) const
    {
        *len = m_datalen;
        return m_data;
    };

    private:
    uint32_t m_plugin_id;
    const char* m_name;
    void* m_data;
    uint32_t m_datalen;
};

class asyncevent_e_decoder
{
    public:
    FALCOSECURITY_INLINE
    asyncevent_e_decoder(const falcosecurity::event_reader& r)
    {
        if(r.get_type() != 402)
        {
            throw std::invalid_argument("invalid event type conversion in "
                                        "event decoder: requested=" +
                                        std::to_string(402) + ", actual=" +
                                        std::to_string(r.get_type()));
        }

        uint8_t* parambuf = ((uint8_t*)r.get_buf() + 26);
        parambuf += sizeof(uint32_t);
        uint32_t namelen = *(uint32_t*)parambuf;
        parambuf += sizeof(uint32_t);
        m_datalen = *(uint32_t*)parambuf;

        parambuf += sizeof(uint32_t);
        m_plugin_id = *(uint32_t*)parambuf;
        parambuf += sizeof(uint32_t);
        m_name = (const char*)parambuf;
        parambuf += namelen;
        m_data = (void*)parambuf;
    }
    FALCOSECURITY_INLINE
    asyncevent_e_decoder(asyncevent_e_decoder&&) = default;
    FALCOSECURITY_INLINE
    asyncevent_e_decoder& operator=(asyncevent_e_decoder&&) = delete;
    FALCOSECURITY_INLINE
    asyncevent_e_decoder(const asyncevent_e_decoder&) = default;
    FALCOSECURITY_INLINE
    asyncevent_e_decoder& operator=(const asyncevent_e_decoder&) = delete;

    FALCOSECURITY_INLINE
    uint32_t get_plugin_id() const { return m_plugin_id; }

    FALCOSECURITY_INLINE
    const char* get_name() const { return m_name; };

    FALCOSECURITY_INLINE
    void* get_data(uint32_t* len) const
    {
        *len = m_datalen;
        return m_data;
    };

    private:
    uint32_t m_plugin_id;
    const char* m_name;
    void* m_data;
    uint32_t m_datalen;
};

}; // namespace events
}; // namespace falcosecurity
