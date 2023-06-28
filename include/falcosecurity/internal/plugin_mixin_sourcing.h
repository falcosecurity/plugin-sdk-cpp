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

#include <falcosecurity/events/encoders.h>
#include <falcosecurity/events/decoders.h>
#include <falcosecurity/event_reader.h>
#include <falcosecurity/extract_request.h>
#include <falcosecurity/internal/deps.h>
#include <falcosecurity/types.h>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace falcosecurity
{

namespace _internal
{

template<class PluginInstance>
class plugin_instance_mixin : public PluginInstance
{
    static_assert(std::has_virtual_destructor<PluginInstance>::value,
                  "Plugin instance type must have a virtual destructor");

    public:
    plugin_instance_mixin(PluginInstance i): PluginInstance(i) {}
    plugin_instance_mixin(plugin_instance_mixin&&) = default;
    plugin_instance_mixin& operator=(plugin_instance_mixin&&) = default;
    plugin_instance_mixin(const plugin_instance_mixin&) = default;
    plugin_instance_mixin& operator=(const plugin_instance_mixin&) = default;
    virtual ~plugin_instance_mixin() = default;

    std::string m_progress_fmt_storage;
    falcosecurity::event_writer m_event_writer;
    ss_plugin_event* m_event_ptr;

    FALCOSECURITY_INLINE
    const char* get_progress(uint32_t* progress_pct)
    {
        m_progress_fmt_storage.clear();
        double pct = _get_progress(m_progress_fmt_storage,
                                   static_cast<PluginInstance*>(this));
        *progress_pct = (uint32_t)(pct * 10000);
        return m_progress_fmt_storage.c_str();
    }

    FALCOSECURITY_INLINE
    ss_plugin_rc next_batch(uint32_t* nevts, ss_plugin_event*** evts)
    {
        static_assert(
                std::is_same<falcosecurity::result_code (PluginInstance::*)(
                                     falcosecurity::event_writer&),
                             decltype(&PluginInstance::next_event)>::value,
                "expected signature: falcosecurity::result_code "
                "next_event(event_writer&)");
        auto res = PluginInstance::next_event(m_event_writer);
        switch(res)
        {
        case result_code::SS_PLUGIN_SUCCESS:
            *nevts = 1;
            m_event_ptr = (ss_plugin_event*)m_event_writer.get_buf();
            *evts = &m_event_ptr;
            return static_cast<ss_plugin_rc>(res);
        case result_code::SS_PLUGIN_EOF:
        case result_code::SS_PLUGIN_TIMEOUT:
            *nevts = 0;
            *evts = nullptr;
            return static_cast<ss_plugin_rc>(res);
        default:
            *nevts = 0;
            *evts = nullptr;
            return ss_plugin_rc::SS_PLUGIN_FAILURE;
        }
    }

    private:
    template<typename T>
    FALCOSECURITY_INLINE auto _get_progress(std::string& fmt, T* o)
            -> decltype(o->get_progress(fmt))
    {
        static_assert(std::is_same<double (T::*)(std::string&),
                                   decltype(&T::get_progress)>::value,
                      "expected signature: double get_progress(std::string&)");
        return o->get_progress(fmt);
    }

    FALCOSECURITY_INLINE
    auto _get_progress(std::string& fmt, ...) -> double
    {
        fmt.clear();
        return 0.0;
    }
};

template<class Plugin, class Base> class plugin_mixin_sourcing : public Base
{
    static_assert(std::has_virtual_destructor<Plugin>::value,
                  "Plugin type must have a virtual destructor");

    public:
    plugin_mixin_sourcing() = default;
    plugin_mixin_sourcing(plugin_mixin_sourcing&&) = default;
    plugin_mixin_sourcing& operator=(plugin_mixin_sourcing&&) = default;
    plugin_mixin_sourcing(const plugin_mixin_sourcing&) = default;
    plugin_mixin_sourcing& operator=(const plugin_mixin_sourcing&) = default;
    virtual ~plugin_mixin_sourcing() = default;

    std::string m_event_source_storage;
    std::string m_event_tostr_storage;
    std::string m_open_params_storage;

    FALCOSECURITY_INLINE
    uint32_t get_id() noexcept { return _get_id(static_cast<Plugin*>(this)); }

    FALCOSECURITY_INLINE
    const char* get_event_source() noexcept
    {
        m_event_source_storage = _get_event_source(static_cast<Plugin*>(this));
        return m_event_source_storage.c_str();
    }

    FALCOSECURITY_INLINE
    const char* list_open_params(ss_plugin_rc* rc)
    {
        FALCOSECURITY_CATCH_ALL(Base::m_last_err_storage, {
            auto arr = nlohmann::json::array();
            auto params = _list_open_params(static_cast<Plugin*>(this));
            for(const auto& p : params)
            {
                nlohmann::json entry;
                entry["value"] = p.value;
                entry["desc"] = p.description;
                if(!p.separator.empty())
                {
                    entry["separator"] = p.separator;
                }
                arr.push_back(entry);
            }
            m_open_params_storage = arr.dump();
            *rc = ss_plugin_rc::SS_PLUGIN_SUCCESS;
            return m_open_params_storage.c_str();
        });
        *rc = ss_plugin_rc::SS_PLUGIN_FAILURE;
        return NULL;
    }

    FALCOSECURITY_INLINE
    const char* event_to_string(const ss_plugin_event_input* evt)
    {
        FALCOSECURITY_CATCH_ALL(Base::m_last_err_storage, {
            m_event_tostr_storage =
                    _event_to_string(evt, static_cast<Plugin*>(this));
            return m_event_tostr_storage.c_str();
        });
        m_event_tostr_storage = "event to string failure";
        return m_event_tostr_storage.c_str();
    }

    template<class PluginInstance>
    FALCOSECURITY_INLINE ss_instance_t* open(const char* params,
                                             ss_plugin_rc* rc)
    {
        static_assert(std::is_same<std::unique_ptr<PluginInstance> (Plugin::*)(
                                           const std::string&),
                                   decltype(&Plugin::open)>::value,
                      "expected signature: std::unique_ptr<PluginInstance> "
                      "open(const std::string&)");
        FALCOSECURITY_CATCH_ALL(Base::m_last_err_storage, {
            auto instance = Plugin::open(params);
            if(instance)
            {
                auto res = new plugin_instance_mixin<PluginInstance>(
                        *instance.get());
                *rc = ss_plugin_rc::SS_PLUGIN_SUCCESS;
                return static_cast<ss_instance_t*>(res);
            }
        });
        *rc = ss_plugin_rc::SS_PLUGIN_FAILURE;
        return NULL;
    }

    // todo(jasondellaluce): should we have an explicit "close()" function for
    // catching erros?
    template<class PluginInstance>
    FALCOSECURITY_INLINE void close(ss_instance_t* h)
    {
        auto i = static_cast<plugin_instance_mixin<PluginInstance>*>(h);
        delete i;
    }

    template<class PluginInstance>
    FALCOSECURITY_INLINE const char* get_progress(ss_instance_t* h,
                                                  uint32_t* progress_pct)
    {
        auto i = static_cast<plugin_instance_mixin<PluginInstance>*>(h);
        return i->get_progress(progress_pct);
    }

    template<class PluginInstance>
    FALCOSECURITY_INLINE ss_plugin_rc next_batch(ss_instance_t* h,
                                                 uint32_t* nevts,
                                                 ss_plugin_event*** evts)
    {
        auto i = static_cast<plugin_instance_mixin<PluginInstance>*>(h);
        return i->next_batch(nevts, evts);
    }

    private:
    template<typename T>
    FALCOSECURITY_INLINE auto _get_id(T* o) -> decltype(o->get_id())
    {
        static_assert(
                std::is_same<uint32_t (T::*)(), decltype(&T::get_id)>::value,
                "expected signature: uint32_t get_id()");
        return o->get_id();
    }

    FALCOSECURITY_INLINE
    auto _get_id(...) -> uint32_t { return 0; }

    template<typename T>
    FALCOSECURITY_INLINE auto _get_event_source(T* o)
            -> decltype(o->get_event_source())
    {
        static_assert(std::is_same<std::string (T::*)(),
                                   decltype(&T::get_event_source)>::value,
                      "expected signature: std::string get_event_source()");
        return o->get_event_source();
    }

    FALCOSECURITY_INLINE
    auto _get_event_source(...) -> std::string { return ""; }

    template<typename T>
    FALCOSECURITY_INLINE auto _list_open_params(T* o)
            -> decltype(o->list_open_params())
    {
        static_assert(std::is_same<std::vector<open_param> (T::*)(),
                                   decltype(&T::list_open_params)>::value,
                      "expected signature: std::vector<open_param> "
                      "list_open_params()");
        return o->list_open_params();
    }

    FALCOSECURITY_INLINE
    auto _list_open_params(...) -> std::vector<open_param> { return {}; }

    template<typename T>
    FALCOSECURITY_INLINE auto _event_to_string(const ss_plugin_event_input* evt,
                                               T* o)
            -> decltype(o->event_to_string(
                    falcosecurity::event_reader(nullptr)))
    {
        static_assert(std::is_same<std::string (T::*)(
                                           const falcosecurity::event_reader&),
                                   decltype(&T::event_to_string)>::value,
                      "expected signature: std::string event_to_string(const "
                      "falcosecurity::event_reader&)");
        falcosecurity::event_reader r(evt);
        return o->event_to_string(r);
    }

    FALCOSECURITY_INLINE
    auto _event_to_string(const ss_plugin_event_input* evt, ...) -> std::string
    {
        return "";
    }
};

}; // namespace _internal
}; // namespace falcosecurity
