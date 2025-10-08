// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <falcosecurity/inputs.h>
#include <falcosecurity/internal/deps.h>
#include <falcosecurity/internal/hacks.h>
#include <falcosecurity/types.h>
#include <string>
#include <type_traits>
#include <vector>

namespace falcosecurity
{
namespace _internal
{

static const std::vector<metric> metrics_empty = {};

template<class Plugin> class plugin_mixin_common : public Plugin
{
    static_assert(std::has_virtual_destructor<Plugin>::value,
                  "Plugin type must have a virtual destructor");

    public:
    plugin_mixin_common() = default;
    plugin_mixin_common(plugin_mixin_common&&) = default;
    plugin_mixin_common& operator=(plugin_mixin_common&&) = default;
    plugin_mixin_common(const plugin_mixin_common&) = default;
    plugin_mixin_common& operator=(const plugin_mixin_common&) = default;
    virtual ~plugin_mixin_common() = default;

    std::string m_str_storage;
    std::string m_last_err_storage;
    falcosecurity::init_schema m_init_schema_storage;
    std::vector<falcosecurity::_internal::ss_plugin_metric> m_metrics_storage;

    FALCOSECURITY_INLINE
    const char* get_required_api_version() noexcept
    {
        m_str_storage = _get_required_api_version(static_cast<Plugin*>(this));
        return m_str_storage.c_str();
    }

    FALCOSECURITY_INLINE
    const char* get_version() noexcept
    {
        static_assert(std::is_same<std::string (Plugin::*)(),
                                   decltype(&Plugin::get_version)>::value,
                      "expected signature: std::string get_version()");
        m_str_storage = Plugin::get_version();
        return m_str_storage.c_str();
    }

    FALCOSECURITY_INLINE
    const char* get_name() noexcept
    {
        static_assert(std::is_same<std::string (Plugin::*)(),
                                   decltype(&Plugin::get_name)>::value,
                      "expected signature: std::string get_name()");
        m_str_storage = Plugin::get_name();
        return m_str_storage.c_str();
    }

    FALCOSECURITY_INLINE
    const char* get_contact() noexcept
    {
        static_assert(std::is_same<std::string (Plugin::*)(),
                                   decltype(&Plugin::get_contact)>::value,
                      "expected signature: std::string get_contact()");
        m_str_storage = Plugin::get_contact();
        return m_str_storage.c_str();
    }

    FALCOSECURITY_INLINE
    const char* get_description() noexcept
    {
        static_assert(std::is_same<std::string (Plugin::*)(),
                                   decltype(&Plugin::get_description)>::value,
                      "expected signature: std::string get_description()");
        m_str_storage = Plugin::get_description();
        return m_str_storage.c_str();
    }

    FALCOSECURITY_INLINE
    const char* get_init_schema(ss_plugin_schema_type* st) noexcept
    {
        m_init_schema_storage = _get_init_schema(static_cast<Plugin*>(this));
        *st = static_cast<ss_plugin_schema_type>(
                m_init_schema_storage.schema_type);
        return m_init_schema_storage.schema.c_str();
    }

    FALCOSECURITY_INLINE
    const char* get_last_error() noexcept
    {
        FALCOSECURITY_CATCH_ALL(m_last_err_storage, {
            auto err = _get_last_error(static_cast<Plugin*>(this));
            if(!err.empty() || m_last_err_storage.empty())
            {
                m_last_err_storage = err;
            }
        });
        return m_last_err_storage.c_str();
    }

    ss_plugin_rc init(const ss_plugin_init_input* input) noexcept
    {
        static_assert(std::is_same<bool (Plugin::*)(falcosecurity::init_input&),
                                   decltype(&Plugin::init)>::value,
                      "expected signature: bool init(const "
                      "falcosecurity::init_input) "
                      "const");
        FALCOSECURITY_CATCH_ALL(m_last_err_storage, {
            falcosecurity::init_input in(input);
            if(Plugin::init(in))
            {
                return ss_plugin_rc::SS_PLUGIN_SUCCESS;
            }
        });
        return ss_plugin_rc::SS_PLUGIN_FAILURE;
    }

    FALCOSECURITY_INLINE
    void destroy() noexcept { _destroy(static_cast<Plugin*>(this)); }

    FALCOSECURITY_INLINE
    ss_plugin_rc set_config(const ss_plugin_set_config_input* input) noexcept
    {
        falcosecurity::set_config_input in(input);
        if(_set_config(in, static_cast<Plugin*>(this)))
        {
            return ss_plugin_rc::SS_PLUGIN_SUCCESS;
        }
        return ss_plugin_rc::SS_PLUGIN_FAILURE;
    }

    FALCOSECURITY_INLINE
    ss_plugin_metric* get_metrics(uint32_t* num_metrics) noexcept
    {
        m_metrics_storage.clear();

        for(const auto& metric : _get_metrics(static_cast<Plugin*>(this)))
        {
            falcosecurity::_internal::ss_plugin_metric m;
            m.name = metric.name.c_str();
            m.type = metric.type;
            m.value = metric.value;
            m.value_type = metric.value_type;

            m_metrics_storage.push_back(m);
        }

        *num_metrics = m_metrics_storage.size();
        return m_metrics_storage.data();
    }

    FALCOSECURITY_INLINE
    const char* get_required_event_schema_version() noexcept
    {
        auto result =
                _get_required_event_schema_version(static_cast<Plugin*>(this));
        if(result.empty())
        {
            return nullptr;
        }
        m_str_storage = result;
        return m_str_storage.c_str();
    }

    private:
    template<typename T>
    FALCOSECURITY_INLINE auto _destroy(T* o) -> decltype(o->destroy())
    {
        static_assert(std::is_same<void (T::*)(), decltype(&T::destroy)>::value,
                      "expected signature: void destroy()");
        return o->destroy();
    }

    FALCOSECURITY_INLINE
    auto _destroy(...) -> void {}

    template<typename T>
    FALCOSECURITY_INLINE auto _get_required_api_version(T* o)
            -> decltype(o->get_required_api_version())
    {
        static_assert(
                std::is_same<std::string (T::*)(),
                             decltype(&T::get_required_api_version)>::value,
                "expected signature: std::string get_required_api_version()");
        return o->get_required_api_version();
    }

    FALCOSECURITY_INLINE
    auto _get_required_api_version(...) -> std::string
    {
        static std::string v = PLUGIN_API_VERSION_STR;
        return v;
    }

    template<typename T>
    FALCOSECURITY_INLINE auto _get_init_schema(T* o)
            -> decltype(o->get_init_schema())
    {
        static_assert(std::is_same<falcosecurity::init_schema (T::*)(),
                                   decltype(&T::get_init_schema)>::value,
                      "expected signature: falcosecurity::init_schema "
                      "get_init_schema()");
        return o->get_init_schema();
    }

    FALCOSECURITY_INLINE
    auto _get_init_schema(...) -> falcosecurity::init_schema
    {
        return falcosecurity::init_schema();
    }

    template<typename T>
    FALCOSECURITY_INLINE auto _get_last_error(T* o)
            -> decltype(o->get_last_error())
    {
        static_assert(std::is_same<std::string (T::*)(),
                                   decltype(&T::get_last_error)>::value,
                      "expected signature: std::string get_last_error()");
        return o->get_last_error();
    }

    FALCOSECURITY_INLINE
    auto _get_last_error(...) -> std::string
    {
        static std::string v = "";
        return v;
    }

    template<typename T>
    FALCOSECURITY_INLINE auto _set_config(falcosecurity::set_config_input& in,
                                          T* o) -> decltype(o->set_config(in))
    {
        static_assert(
                std::is_same<bool (T::*)(falcosecurity::set_config_input&),
                             decltype(&T::set_config)>::value,
                "expected signature: bool set_config(const "
                "falcosecurity::set_config_input) ");
        return o->set_config(in);
    }

    FALCOSECURITY_INLINE
    auto _set_config(...) -> bool { return false; }

    template<typename T>
    FALCOSECURITY_INLINE auto _get_metrics(T* o) -> decltype(o->get_metrics())
    {
        static_assert(
                std::is_same<const std::vector<falcosecurity::metric>& (T::*)(),
                             decltype(&T::get_metrics)>::value,
                "expected signature: const std::vector<falcosecurity::metric>& "
                "get_metrics()");
        return o->get_metrics();
    }

    FALCOSECURITY_INLINE
    auto _get_metrics(...) -> const std::vector<falcosecurity::metric>&
    {
        return metrics_empty;
    }

    template<typename T>
    FALCOSECURITY_INLINE auto _get_required_event_schema_version(T* o)
            -> decltype(o->get_required_event_schema_version())
    {
        static_assert(
                std::is_same<
                        std::string (T::*)(),
                        decltype(&T::get_required_event_schema_version)>::value,
                "expected signature: std::string "
                "get_required_event_schema_version()");
        return o->get_required_event_schema_version();
    }

    FALCOSECURITY_INLINE
    auto _get_required_event_schema_version(...) -> std::string { return ""; }
};

}; // namespace _internal
}; // namespace falcosecurity
