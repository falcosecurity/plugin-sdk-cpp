// SPDX-License-Identifier: Apache-2.0
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
#include <falcosecurity/event_writer.h>
#include <stdexcept>
#include <string>

namespace falcosecurity
{

class async_event_handler
{
    public:
    FALCOSECURITY_INLINE
    async_event_handler(
            falcosecurity::_internal::ss_plugin_owner_t* o,
            const falcosecurity::_internal::ss_plugin_async_event_handler_t h):
            m_owner(o),
            m_handler(h), m_writer()
    {
    }
    FALCOSECURITY_INLINE
    async_event_handler(async_event_handler&&) = default;
    FALCOSECURITY_INLINE
    async_event_handler& operator=(async_event_handler&&) = default;
    FALCOSECURITY_INLINE
    async_event_handler(const async_event_handler& s) = delete;
    FALCOSECURITY_INLINE
    async_event_handler& operator=(const async_event_handler& s) = delete;

    FALCOSECURITY_INLINE
    event_writer& writer() { return m_writer; }

    FALCOSECURITY_INLINE
    void push()
    {
        char err[PLUGIN_MAX_ERRLEN];
        if(m_handler(m_owner,
                     (const falcosecurity::_internal::ss_plugin_event*)
                             m_writer.get_buf(),
                     err) !=
           falcosecurity::_internal::ss_plugin_rc::SS_PLUGIN_SUCCESS)
        {
            std::string msg = "async event handler failure";
            if(*err != '\0')
            {
                msg += ": ";
                msg += err;
            }
            throw falcosecurity::plugin_exception(msg);
        }
    }

    private:
    falcosecurity::_internal::ss_plugin_owner_t* m_owner;
    falcosecurity::_internal::ss_plugin_async_event_handler_t m_handler;
    event_writer m_writer;
};

class async_event_handler_factory
{
    public:
    FALCOSECURITY_INLINE
    async_event_handler_factory(
            falcosecurity::_internal::ss_plugin_owner_t* o,
            const falcosecurity::_internal::ss_plugin_async_event_handler_t h):
            m_owner(o),
            m_handler(h)
    {
    }
    FALCOSECURITY_INLINE
    async_event_handler_factory(async_event_handler_factory&&) = default;
    FALCOSECURITY_INLINE
    async_event_handler_factory&
    operator=(async_event_handler_factory&&) = default;
    FALCOSECURITY_INLINE
    async_event_handler_factory(const async_event_handler_factory& s) = default;
    FALCOSECURITY_INLINE
    async_event_handler_factory&
    operator=(const async_event_handler_factory& s) = default;

    FALCOSECURITY_INLINE
    std::unique_ptr<async_event_handler> new_handler() const
    {
        return std::unique_ptr<async_event_handler>(
                new async_event_handler(m_owner, m_handler));
    }

    private:
    falcosecurity::_internal::ss_plugin_owner_t* m_owner;
    falcosecurity::_internal::ss_plugin_async_event_handler_t m_handler;
};

}; // namespace falcosecurity
