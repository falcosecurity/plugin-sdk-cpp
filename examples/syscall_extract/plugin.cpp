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

    std::string get_name() { return "syscall-extract-example"; }

    std::string get_version() { return "0.1.0"; }

    std::string get_description() { return "some description"; }

    std::string get_contact() { return "some contact"; }

    // (optional)
    std::vector<falcosecurity::event_type> get_extract_event_types()
    {
        return {};
    }

    // (optional)
    std::vector<std::string> get_extract_event_sources() { return {"syscall"}; }

    std::vector<falcosecurity::field_info> get_fields()
    {
        using ft = falcosecurity::field_value_type;
        return {
                {ft::FTYPE_BOOL, "sample.is_open", "Is Open Type",
                 "Value is true if event is of open family"},
                {ft::FTYPE_UINT64, "sample.open_count", "Open Type Count",
                 "Counter for all the events of open family in the event's "
                 "thread thread"},
        };
    }

    bool init(falcosecurity::init_input& i)
    {
        using st = falcosecurity::state_value_type;
        auto& t = i.tables();
        m_threads_table = t.get_table("threads", st::SS_PLUGIN_ST_INT64);
        m_threads_field_opencount = m_threads_table.get_field(
                t.fields(), "open_evt_count", st::SS_PLUGIN_ST_UINT64);
        return true;
    }

    bool extract(const falcosecurity::extract_fields_input& in)
    {
        auto& evt = in.get_event_reader();
        auto& req = in.get_extract_request();
        switch(req.get_field_id())
        {
        case 0: // sample.is_open
            req.set_value(evt_type_is_open(evt.get_type()));
            return true;
        case 1: // sample.open_count
        {
            auto& tr = in.get_table_reader();
            auto tinfo = m_threads_table.get_entry(tr, (int64_t)evt.get_tid());
            uint64_t count = 0;
            m_threads_field_opencount.read_value(tr, tinfo, count);
            req.set_value(count);
            return true;
        }
        default:
            break;
        }

        return false;
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
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(my_plugin);
