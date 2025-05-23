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

#include <falcosecurity/events/types.h>
#include <falcosecurity/exception.h>
#include <falcosecurity/internal/deps.h>
#include <cstdbool>
#include <cstdint>
#include <string>
#include <vector>

namespace falcosecurity
{

using result_code = _internal::ss_plugin_rc;

using init_schema_type = _internal::ss_plugin_schema_type;

using field_value_type = _internal::ss_plugin_field_type;

using state_value_type = _internal::ss_plugin_state_type;

using log_severity = _internal::ss_plugin_log_severity;

using owner_type = _internal::ss_plugin_owner_t*;

using log_fn_type = _internal::ss_plugin_log_fn_t;

using metric_type = _internal::ss_plugin_metric_type;

using metric_value_type = _internal::ss_plugin_metric_value_type;

using metric_value = _internal::ss_plugin_metric_value;

struct logger
{
    FALCOSECURITY_INLINE
    logger(owner_type o, log_fn_type f):
            owner(o), log_fn(f != nullptr ? f : (log_fn_type)log_discard)
    {
    }
    FALCOSECURITY_INLINE
    logger() = default;
    FALCOSECURITY_INLINE
    logger(logger&&) = default;
    FALCOSECURITY_INLINE
    logger& operator=(logger&&) = default;
    FALCOSECURITY_INLINE
    logger(const logger&) = default;
    FALCOSECURITY_INLINE
    logger& operator=(const logger&) = default;

    FALCOSECURITY_INLINE
    void log(const std::string& component, const std::string& msg,
             log_severity sev = log_severity::SS_PLUGIN_LOG_SEV_INFO) noexcept
    {
        log_fn(owner, component.c_str(), msg.c_str(), sev);
    }

    FALCOSECURITY_INLINE
    void log(const std::string& msg,
             log_severity sev = log_severity::SS_PLUGIN_LOG_SEV_INFO) noexcept
    {
        log_fn(owner, NULL, msg.c_str(), sev);
    }

    FALCOSECURITY_INLINE
    void log(const char* component, const char* msg,
             log_severity sev = log_severity::SS_PLUGIN_LOG_SEV_INFO) noexcept
    {
        log_fn(owner, component, msg, sev);
    }

    FALCOSECURITY_INLINE
    void log(const char* msg,
             log_severity sev = log_severity::SS_PLUGIN_LOG_SEV_INFO) noexcept
    {
        log_fn(owner, NULL, msg, sev);
    }

    private:
    FALCOSECURITY_INLINE
    static void log_discard(owner_type* o, const char* c, const char* m,
                            log_severity s)
    {
        // do nothing
    }

    owner_type owner;
    log_fn_type log_fn = (log_fn_type)log_discard;
};

struct init_schema
{
    FALCOSECURITY_INLINE
    init_schema(init_schema_type t, const std::string& s):
            schema_type(t), schema(s)
    {
    }
    FALCOSECURITY_INLINE
    init_schema(): init_schema(init_schema_type::SS_PLUGIN_SCHEMA_NONE, "") {}
    FALCOSECURITY_INLINE
    init_schema(init_schema&&) = default;
    FALCOSECURITY_INLINE
    init_schema& operator=(init_schema&&) = default;
    FALCOSECURITY_INLINE
    init_schema(const init_schema&) = default;
    FALCOSECURITY_INLINE
    init_schema& operator=(const init_schema&) = default;

    init_schema_type schema_type;
    std::string schema;
};

struct field_arg
{
    FALCOSECURITY_INLINE
    field_arg() = default;
    FALCOSECURITY_INLINE
    field_arg(field_arg&&) = default;
    FALCOSECURITY_INLINE
    field_arg& operator=(field_arg&&) = default;
    FALCOSECURITY_INLINE
    field_arg(const field_arg&) = default;
    FALCOSECURITY_INLINE
    field_arg& operator=(const field_arg&) = default;

    bool key = false;
    bool index = false;
    bool required = false;
};

struct field_info
{
    FALCOSECURITY_INLINE
    field_info() = default;
    FALCOSECURITY_INLINE
    field_info(field_value_type t, const std::string& n, const std::string& di,
               const std::string& de, const field_arg& a = field_arg(),
               bool l = false, const std::vector<std::string>& p = {},
               bool o = false):
            type(t),
            name(n), list(l), arg(a), display(di), description(de),
            properties(p), addOutput(o)
    {
    }
    FALCOSECURITY_INLINE
    field_info(field_info&&) = default;
    FALCOSECURITY_INLINE
    field_info& operator=(field_info&&) = default;
    FALCOSECURITY_INLINE
    field_info(const field_info&) = default;
    FALCOSECURITY_INLINE
    field_info& operator=(const field_info&) = default;

    field_value_type type;
    std::string name;
    bool list = false;
    field_arg arg;
    std::string display;
    std::string description;
    std::vector<std::string> properties;
    bool addOutput = false;
};

struct open_param
{
    FALCOSECURITY_INLINE
    open_param() = default;
    FALCOSECURITY_INLINE
    open_param(const std::string& v, const std::string& d,
               const std::string& s = ";"):
            value(v),
            description(d), separator(s)
    {
    }
    FALCOSECURITY_INLINE
    open_param(open_param&&) = default;
    FALCOSECURITY_INLINE
    open_param& operator=(open_param&&) = default;
    FALCOSECURITY_INLINE
    open_param(const open_param&) = default;
    FALCOSECURITY_INLINE
    open_param& operator=(const open_param&) = default;

    std::string value;
    std::string description;
    std::string separator;
};

struct metric
{
    FALCOSECURITY_INLINE
    metric() = default;
    FALCOSECURITY_INLINE
    metric(const std::string& n,
           const metric_type t = metric_type::SS_PLUGIN_METRIC_TYPE_MONOTONIC,
           const metric_value v = metric_value(),
           const metric_value_type vt =
                   metric_value_type::SS_PLUGIN_METRIC_VALUE_TYPE_U64):
            name(n),
            type(t), value(v), value_type(vt)
    {
    }
    FALCOSECURITY_INLINE
    metric(metric&&) = default;
    FALCOSECURITY_INLINE
    metric& operator=(metric&&) = default;
    FALCOSECURITY_INLINE
    metric(const metric&) = default;
    FALCOSECURITY_INLINE
    metric& operator=(const metric&) = default;

    FALCOSECURITY_INLINE
    void set_value(uint32_t v) noexcept
    {
        value.u32 = v;
        value_type = metric_value_type::SS_PLUGIN_METRIC_VALUE_TYPE_U32;
    }

    FALCOSECURITY_INLINE
    void set_value(int32_t v) noexcept
    {
        value.s32 = v;
        value_type = metric_value_type::SS_PLUGIN_METRIC_VALUE_TYPE_S32;
    }

    FALCOSECURITY_INLINE
    void set_value(uint64_t v) noexcept
    {
        value.u64 = v;
        value_type = metric_value_type::SS_PLUGIN_METRIC_VALUE_TYPE_U64;
    }

    FALCOSECURITY_INLINE
    void set_value(int64_t v) noexcept
    {
        value.s64 = v;
        value_type = metric_value_type::SS_PLUGIN_METRIC_VALUE_TYPE_S64;
    }

    FALCOSECURITY_INLINE
    void set_value(double v) noexcept
    {
        value.d = v;
        value_type = metric_value_type::SS_PLUGIN_METRIC_VALUE_TYPE_D;
    }

    FALCOSECURITY_INLINE
    void set_value(float v) noexcept
    {
        value.f = v;
        value_type = metric_value_type::SS_PLUGIN_METRIC_VALUE_TYPE_F;
    }

    std::string name;
    metric_type type;
    metric_value value;
    metric_value_type value_type;
};

static inline std::string to_string(result_code t)
{
    switch(t)
    {
    case result_code::SS_PLUGIN_SUCCESS:
        return "success";
    case result_code::SS_PLUGIN_FAILURE:
        return "failure";
    case result_code::SS_PLUGIN_TIMEOUT:
        return "timeout";
    case result_code::SS_PLUGIN_EOF:
        return "eof";
    case result_code::SS_PLUGIN_NOT_SUPPORTED:
        return "not supported";
    default:
        throw falcosecurity::plugin_exception("unknown result code: " +
                                              std::to_string((size_t)t));
    }
}

static inline std::string to_string(init_schema_type t)
{
    switch(t)
    {
    case init_schema_type::SS_PLUGIN_SCHEMA_NONE:
        return "none";
    case init_schema_type::SS_PLUGIN_SCHEMA_JSON:
        return "json";
    default:
        throw falcosecurity::plugin_exception("unknown init schema type: " +
                                              std::to_string((size_t)t));
    }
}

static inline std::string to_string(field_value_type t)
{
    switch(t)
    {
    case field_value_type::FTYPE_UINT64:
        return "uint64";
    case field_value_type::FTYPE_STRING:
        return "string";
    case field_value_type::FTYPE_RELTIME:
        return "reltime";
    case field_value_type::FTYPE_ABSTIME:
        return "abstime";
    case field_value_type::FTYPE_BOOL:
        return "bool";
    case field_value_type::FTYPE_IPADDR:
        return "ipaddr";
    case field_value_type::FTYPE_IPNET:
        return "ipnet";
    default:
        throw falcosecurity::plugin_exception("unknown field value type: " +
                                              std::to_string((size_t)t));
    }
}

static inline std::string to_string(state_value_type t)
{
    switch(t)
    {
    case state_value_type::SS_PLUGIN_ST_INT8:
        return "int8";
    case state_value_type::SS_PLUGIN_ST_INT16:
        return "int16";
    case state_value_type::SS_PLUGIN_ST_INT32:
        return "int32";
    case state_value_type::SS_PLUGIN_ST_INT64:
        return "int64";
    case state_value_type::SS_PLUGIN_ST_UINT8:
        return "uint8";
    case state_value_type::SS_PLUGIN_ST_UINT16:
        return "uint16";
    case state_value_type::SS_PLUGIN_ST_UINT32:
        return "uint32";
    case state_value_type::SS_PLUGIN_ST_UINT64:
        return "uint64";
    case state_value_type::SS_PLUGIN_ST_STRING:
        return "string";
    case state_value_type::SS_PLUGIN_ST_BOOL:
        return "bool";
    default:
        throw falcosecurity::plugin_exception("unknown state value type: " +
                                              std::to_string((size_t)t));
    }
}

}; // namespace falcosecurity
