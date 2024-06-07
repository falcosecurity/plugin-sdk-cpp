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

#include <falcosecurity/sdk.h>

// todo(jasondellaluce): support these in the SDK
using _et = falcosecurity::event_type;
constexpr auto PPME_SYSCALL_OPEN_E = (_et)2;
constexpr auto PPME_SYSCALL_OPEN_X = (_et)3;
constexpr auto PPME_SYSCALL_OPENAT_E = (_et)102;
constexpr auto PPME_SYSCALL_OPENAT_X = (_et)103;
constexpr auto PPME_SYSCALL_OPENAT_2_E = (_et)306;
constexpr auto PPME_SYSCALL_OPENAT_2_X = (_et)307;
constexpr auto PPME_SYSCALL_OPENAT2_E = (_et)326;
constexpr auto PPME_SYSCALL_OPENAT2_X = (_et)327;
constexpr auto PPME_SYSCALL_OPEN_BY_HANDLE_AT_E = (_et)336;
constexpr auto PPME_SYSCALL_OPEN_BY_HANDLE_AT_X = (_et)337;

class my_plugin
{
    public:
    virtual ~my_plugin() = default;

    std::string get_name() { return "syscall-parse-example"; }

    std::string get_version() { return "0.1.0"; }

    std::string get_description() { return "some description"; }

    std::string get_contact() { return "some contact"; }

    // (optional)
    std::vector<falcosecurity::event_type> get_parse_event_types()
    {
        return {
                PPME_SYSCALL_OPEN_E,
                PPME_SYSCALL_OPEN_X,
                PPME_SYSCALL_OPENAT_E,
                PPME_SYSCALL_OPENAT_X,
                PPME_SYSCALL_OPENAT_2_E,
                PPME_SYSCALL_OPENAT_2_X,
                PPME_SYSCALL_OPENAT2_E,
                PPME_SYSCALL_OPENAT2_X,
                PPME_SYSCALL_OPEN_BY_HANDLE_AT_E,
                PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
        };
    }

    // (optional)
    std::vector<std::string> get_parse_event_sources() { return {"syscall"}; }

    // (optional)
    bool set_config(falcosecurity::set_config_input& i)
    {
        logger.log("new config!");
        return true;
    }

    // (optional)
    const std::vector<falcosecurity::metric>& get_metrics()
    {
        return m_metrics;
    }

    // (optional)
    void destroy() { logger.log("plugin destroyed"); }

    bool init(falcosecurity::init_input& i)
    {
        logger = i.get_logger();
        logger.log("plugin initialized");

        using st = falcosecurity::state_value_type;
        auto& t = i.tables();
        m_threads_table = t.get_table("threads", st::SS_PLUGIN_ST_INT64);
        m_threads_field_opencount = m_threads_table.add_field(
                t.fields(), "open_evt_count", st::SS_PLUGIN_ST_UINT64);

        falcosecurity::metric m("dummy_metric",
                                falcosecurity::metric_type::
                                        SS_PLUGIN_METRIC_TYPE_NON_MONOTONIC);
        m.set_value(-123.001);
        m_metrics.push_back(m);

        falcosecurity::metric ec("evt_count");
        m_metrics.push_back(ec);

        return true;
    }

    bool parse_event(const falcosecurity::parse_event_input& in)
    {
        // update counter for current thread
        auto& evt = in.get_event_reader();
        if(evt_type_is_open(evt.get_type()))
        {
            auto& tr = in.get_table_reader();
            auto& tw = in.get_table_writer();

            auto tinfo = m_threads_table.get_entry(tr, (int64_t)evt.get_tid());

            uint64_t count = 0;
            m_threads_field_opencount.read_value(tr, tinfo, count);
            count++;
            m_threads_field_opencount.write_value(tw, tinfo, count);

            // update 'evt_count' metric
            m_metrics.at(1).set_value(count);
        }
        return true;
    }

    private:
    inline bool evt_type_is_open(falcosecurity::event_type t)
    {
        return t == PPME_SYSCALL_OPEN_E || t == PPME_SYSCALL_OPEN_X ||
               t == PPME_SYSCALL_OPENAT_E || t == PPME_SYSCALL_OPENAT_X ||
               t == PPME_SYSCALL_OPENAT_2_E || t == PPME_SYSCALL_OPENAT_2_X ||
               t == PPME_SYSCALL_OPENAT2_E || t == PPME_SYSCALL_OPENAT2_X ||
               t == PPME_SYSCALL_OPEN_BY_HANDLE_AT_E ||
               t == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X;
    }

    falcosecurity::table m_threads_table;
    falcosecurity::table_field m_threads_field_opencount;
    falcosecurity::logger logger;
    std::vector<falcosecurity::metric> m_metrics;
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_EVENT_PARSING(my_plugin);
