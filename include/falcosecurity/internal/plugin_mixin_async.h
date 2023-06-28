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
#include <falcosecurity/events/encoders.h>
#include <falcosecurity/exception.h>
#include <falcosecurity/internal/deps.h>
#include <falcosecurity/internal/hacks.h>
#include <falcosecurity/types.h>
#include <functional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace falcosecurity
{

namespace _internal
{

template<class Plugin, class Base> class plugin_mixin_async : public Base
{
    static_assert(std::has_virtual_destructor<Plugin>::value,
                  "Plugin type must have a virtual destructor");

    public:
    plugin_mixin_async() = default;
    plugin_mixin_async(plugin_mixin_async&&) = default;
    plugin_mixin_async& operator=(plugin_mixin_async&&) = default;
    plugin_mixin_async(const plugin_mixin_async&) = default;
    plugin_mixin_async& operator=(const plugin_mixin_async&) = default;
    virtual ~plugin_mixin_async()
    {
        if(m_async_started)
        {
            Plugin::stop_async_events();
        }
    }

    bool m_async_started = false;
    std::string m_async_events_storage;
    std::string m_async_event_sources_storage;
    event_writer m_event_writer;

    FALCOSECURITY_INLINE
    const char* get_async_events() noexcept
    {
        static_assert(std::is_same<std::vector<std::string> (Plugin::*)(),
                                   decltype(&Plugin::get_async_events)>::value,
                      "expected signature: std::vector<std::string> "
                      "get_async_events()");
        auto arr = nlohmann::json::array();
        for(const auto& src : Plugin::get_async_events())
        {
            nlohmann::json s = src;
            arr.push_back(s);
        }
        m_async_events_storage = arr.dump();
        return m_async_events_storage.c_str();
    }

    FALCOSECURITY_INLINE
    const char* get_async_event_sources() noexcept
    {
        auto arr = nlohmann::json::array();
        for(const auto& src :
            _get_async_event_sources(static_cast<Plugin*>(this)))
        {
            nlohmann::json s = src;
            arr.push_back(s);
        }
        m_async_event_sources_storage = arr.dump();
        return m_async_event_sources_storage.c_str();
    }

    FALCOSECURITY_INLINE
    ss_plugin_rc
    set_async_event_handler(ss_plugin_owner_t* o,
                            const ss_plugin_async_event_handler_t h)
    {
        static_assert(
                std::is_same<bool (Plugin::*)(falcosecurity::event_writer&,
                                              std::function<void(void)>),
                             decltype(&Plugin::start_async_events)>::value,
                "expected signature: bool "
                "start_async_events(falcosecurity::event_writer&,std::function<"
                "void(void)>");
        static_assert(std::is_same<bool (Plugin::*)() noexcept,
                                   decltype(&Plugin::stop_async_events)>::value,
                      "expected signature: bool stop_async_events() noexcept");
        if(m_async_started)
        {
            if(!Plugin::stop_async_events())
            {
                Base::m_last_err_storage = "async stop start failure";
                return ss_plugin_rc::SS_PLUGIN_FAILURE;
            }
            m_async_started = false;
        }

        if(h)
        {
            auto submit = [this, o, h]()
            {
                char err[PLUGIN_MAX_ERRLEN];
                if(h(o, (const ss_plugin_event*)this->m_event_writer.get_buf(),
                     err) != ss_plugin_rc::SS_PLUGIN_SUCCESS)
                {
                    std::string msg = "async event handler failure";
                    if(*err != '\0')
                    {
                        msg += ": ";
                        msg += err;
                    }
                    throw falcosecurity::plugin_exception(msg);
                }
            };
            FALCOSECURITY_CATCH_ALL(Base::m_last_err_storage, {
                if(!Plugin::start_async_events(m_event_writer, submit))
                {
                    Base::m_last_err_storage = "async events start failure";
                    return ss_plugin_rc::SS_PLUGIN_FAILURE;
                }
                m_async_started = true;
                return SS_PLUGIN_SUCCESS;
            });
            return SS_PLUGIN_FAILURE;
        }
        return SS_PLUGIN_SUCCESS;
    }

    private:
    template<typename T>
    FALCOSECURITY_INLINE auto _get_async_event_sources(T* o)
            -> decltype(o->get_async_event_sources())
    {
        static_assert(
                std::is_same<std::vector<std::string> (T::*)(),
                             decltype(&T::get_async_event_sources)>::value,
                "expected signature: std::vector<std::string> "
                "get_async_event_sources()");
        return o->get_async_event_sources();
    }

    FALCOSECURITY_INLINE
    auto _get_async_event_sources(...) -> std::vector<std::string>
    {
        return {};
    }
};

}; // namespace _internal
}; // namespace falcosecurity
