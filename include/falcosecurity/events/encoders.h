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

#include <falcosecurity/event_writer.h>
#include <falcosecurity/internal/hacks.h>
#include <falcosecurity/types.h>
#include <stdexcept>
#include <string>

namespace falcosecurity
{
namespace events
{

class pluginevent_e_encoder
{
    public:
    FALCOSECURITY_INLINE
    pluginevent_e_encoder() = default;
    FALCOSECURITY_INLINE
    pluginevent_e_encoder(pluginevent_e_encoder&&) = default;
    FALCOSECURITY_INLINE
    pluginevent_e_encoder& operator=(pluginevent_e_encoder&&) = default;
    FALCOSECURITY_INLINE
    pluginevent_e_encoder(const pluginevent_e_encoder& s) = default;
    FALCOSECURITY_INLINE
    pluginevent_e_encoder& operator=(const pluginevent_e_encoder& s) = default;

    FALCOSECURITY_INLINE
    void encode(falcosecurity::event_writer& w) const
    {
        w.grow(26 + (sizeof(uint32_t) * 2) + sizeof(uint32_t) + m_datalen);
        uint8_t* evt = (uint8_t*)w.get_buf();
        uint8_t* parambuf = evt + 26;
        *((uint64_t*)(evt + 0)) = m_ts;
        *((uint64_t*)(evt + 8)) = m_tid;
        *((uint16_t*)(evt + 20)) = 322;
        *((uint32_t*)(evt + 22)) = 2;
        *((uint32_t*)parambuf) = sizeof(uint32_t);
        parambuf += sizeof(uint32_t);
        *((uint32_t*)parambuf) = m_datalen;
        parambuf += sizeof(uint32_t);
        *((uint32_t*)parambuf) = m_plugin_id;
        parambuf += sizeof(uint32_t);
        memcpy(parambuf, m_data, m_datalen);
        parambuf += m_datalen;
        *((uint32_t*)(evt + 16)) = (uint32_t)(parambuf - evt);
    }

    FALCOSECURITY_INLINE
    void set_tid(uint64_t v) { m_tid = v; }

    FALCOSECURITY_INLINE
    void set_ts(uint64_t v) { m_ts = v; }

    FALCOSECURITY_INLINE
    void set_plugin_id(uint32_t v) { m_plugin_id = v; }

    FALCOSECURITY_INLINE
    void set_data(void* v, uint32_t vlen)
    {
        m_data = v;
        m_datalen = vlen;
    }

    private:
    uint64_t m_ts = (uint64_t)-1;
    uint64_t m_tid = (uint64_t)-1;
    uint32_t m_plugin_id = 0;
    void* m_data = nullptr;
    uint32_t m_datalen = 0;
};

class asyncevent_e_encoder
{
    public:
    FALCOSECURITY_INLINE
    asyncevent_e_encoder() = default;
    FALCOSECURITY_INLINE
    asyncevent_e_encoder(asyncevent_e_encoder&&) = default;
    FALCOSECURITY_INLINE
    asyncevent_e_encoder& operator=(asyncevent_e_encoder&&) = default;
    FALCOSECURITY_INLINE
    asyncevent_e_encoder(const asyncevent_e_encoder& s) = default;
    FALCOSECURITY_INLINE
    asyncevent_e_encoder& operator=(const asyncevent_e_encoder& s) = default;

    FALCOSECURITY_INLINE
    void encode(falcosecurity::event_writer& w) const
    {
        w.grow(26 + (sizeof(uint32_t) * 3) + sizeof(uint32_t) +
               (m_name.length() + 1) + m_datalen);
        uint8_t* evt = (uint8_t*)w.get_buf();
        uint8_t* parambuf = evt + 26;
        *((uint64_t*)(evt + 0)) = m_ts;
        *((uint64_t*)(evt + 8)) = m_tid;
        *((uint16_t*)(evt + 20)) = 402;
        *((uint32_t*)(evt + 22)) = 3;
        *((uint32_t*)parambuf) = sizeof(uint32_t);
        parambuf += sizeof(uint32_t);
        *((uint32_t*)parambuf) = m_name.length() + 1;
        parambuf += sizeof(uint32_t);
        *((uint32_t*)parambuf) = m_datalen;
        parambuf += sizeof(uint32_t);
        *((uint32_t*)parambuf) = m_plugin_id;
        parambuf += sizeof(uint32_t);
        memcpy(parambuf, m_name.c_str(), m_name.length() + 1);
        parambuf += m_name.length() + 1;
        memcpy(parambuf, m_data, m_datalen);
        parambuf += m_datalen;
        *((uint32_t*)(evt + 16)) = (uint32_t)(parambuf - evt);
    }

    FALCOSECURITY_INLINE
    void set_tid(uint64_t v) { m_tid = v; }

    FALCOSECURITY_INLINE
    void set_ts(uint64_t v) { m_ts = v; }

    FALCOSECURITY_INLINE
    void set_name(const std::string& v) { m_name = v; }

    FALCOSECURITY_INLINE
    void set_data(void* v, uint32_t vlen)
    {
        m_data = v;
        m_datalen = vlen;
    }

    private:
    uint64_t m_ts = (uint64_t)-1;
    uint64_t m_tid = (uint64_t)-1;
    uint32_t m_plugin_id = 0; // note: can't be set from outside
    std::string m_name;
    void* m_data = nullptr;
    uint32_t m_datalen = 0;
};

}; // namespace events
}; // namespace falcosecurity
