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
#include <iostream>

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

// Exposes a std::vector<std::string> as a table
class my_table : public falcosecurity::plugin_table<my_table, uint64_t>
{
    public:
    my_table(): falcosecurity::plugin_table<my_table, uint64_t>() {};

    std::string& get_name() { return name; }

    uint64_t get_size() { return data.size(); }

    falcosecurity::state_value_type get_key_type()
    {
        return falcosecurity::state_value_type::SS_PLUGIN_ST_UINT64;
    }

    std::vector<falcosecurity::table_field_info> list_fields()
    {
        std::vector<falcosecurity::table_field_info> infos;
        auto fi = falcosecurity::table_field_info(
                falcosecurity::state_value_type::SS_PLUGIN_ST_STRING, "value",
                false);
        infos.push_back(fi);

        return infos;
    }

    falcosecurity::plugin_table_field*
    get_field(const std::string& name,
              falcosecurity::state_value_type data_type)
    {
        return static_cast<falcosecurity::plugin_table_field*>(&data);
    }

    falcosecurity::plugin_table_entry* get_entry(uint64_t key)
    {
        if(data.size() > key)
        {
            return static_cast<falcosecurity::plugin_table_entry*>(
                    (void*)(key + 1));
        }
        return nullptr;
    }

    bool read_entry_field(falcosecurity::plugin_table_entry* e,
                          const falcosecurity::plugin_table_field* f,
                          falcosecurity::plugin_state_data* out)
    {
        auto index = (uint64_t)(e)-1;

        if(data.size() > index)
        {
            auto v = data[index];
            falcosecurity::_internal::write_state_data<std::string>(out, v);

            return true;
        }

        return false;
    }

    std::string name = "my_table";
    std::vector<std::string> data;
};

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
        /*m_threads_table = t.get_table("threads", st::SS_PLUGIN_ST_INT64);
        m_threads_field_opencount = m_threads_table.add_field(
                t.fields(), "open_evt_count", st::SS_PLUGIN_ST_UINT64);

        // get the subtable field accessor
        m_threads_field_file_descriptor = m_threads_table.get_field(
                t.fields(), "file_descriptors", st::SS_PLUGIN_ST_TABLE);

        // add a new custom field to the subtable
        m_file_descriptor_field_custom = t.add_subtable_field(
                m_threads_table, m_threads_field_file_descriptor, "custom",
                st::SS_PLUGIN_ST_STRING);

        m_threads_field_tid = m_threads_table.get_field(
                t.fields(), "tid", st::SS_PLUGIN_ST_UINT64);

        falcosecurity::metric m("dummy_metric",
                                falcosecurity::metric_type::
                                        SS_PLUGIN_METRIC_TYPE_NON_MONOTONIC);
        m.set_value(-123.001);
        m_metrics.push_back(m);

        falcosecurity::metric ec("evt_count");
        m_metrics.push_back(ec);*/

        // add the custom table
        m_table = my_table();
        t.add_table(m_table.get_table_input());

        // add some data to the table
        m_table.data.push_back("dummy0");
        m_table.data.push_back("dummy1");
        m_table.data.push_back("dummy2");

        // get the table fields through the api to check if the conversion works
        m_plugin_table = t.get_table(
                "my_table",
                falcosecurity::state_value_type::SS_PLUGIN_ST_UINT64);

        m_plugin_table_field = m_plugin_table.get_field(
                t.fields(), "value", st::SS_PLUGIN_ST_STRING);

        return true;
    }

    bool parse_event(const falcosecurity::parse_event_input& in)
    {
        auto& tr = in.get_table_reader();

        // test plugin table
        auto entry = m_plugin_table.get_entry(tr, 1);
        std::string out;
        m_plugin_table_field.read_value(tr, entry, out);

        std::fprintf(stderr, "Entry value: %s\n", out.c_str());

        /*if(evt_type_is_open(evt.get_type()))
        {
            auto& tr = in.get_table_reader();
            auto& tw = in.get_table_writer();

            auto tinfo = m_threads_table.get_entry(tr,
            (int64_t)evt.get_tid());

            uint64_t count = 0;
            m_threads_field_opencount.read_value(tr, tinfo, count);
            count++;
            m_threads_field_opencount.write_value(tw, tinfo, count);

            using st = falcosecurity::state_value_type;

            // get the subtable using the access obtained during the init, in
            // this case the fd table of the event tid
            auto fd_table = m_threads_table.get_subtable(
                    tr, m_threads_field_file_descriptor, tinfo,
                    st::SS_PLUGIN_ST_INT64);

            // iterate all the entries in the subtable
            fd_table.iterate_entries(
                    tr,
                    [this, tw](const falcosecurity::table_entry& e)
                    {
                        // writes a dummy value in the custom field of each
                        // entry in the subtable
                        std::string hello = "hello world";
                        m_file_descriptor_field_custom.write_value(tw, e,
                                                                   hello);

                        return true;
                    });

            // update 'evt_count' metric
            m_metrics.at(1).set_value(count);
        }*/
        return true;
    }

    bool capture_open(const falcosecurity::capture_listen_input& in)
    {
        /*auto& tr = in.get_table_reader();
        m_threads_table.iterate_entries(
                tr,
                [this, tr](const falcosecurity::table_entry& e)
                {
                    uint64_t tid;
                    m_threads_field_tid.read_value(tr, e, tid);
                    std::cout << "read thread id: " << std::to_string(tid)
                              << std::endl;
                    return true;
                });*/
        return true;
    }

    bool capture_close(const falcosecurity::capture_listen_input& in)
    {
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
    falcosecurity::table_field m_threads_field_file_descriptor;
    falcosecurity::table_field m_threads_field_tid;

    falcosecurity::table_field m_file_descriptor_field_custom;

    falcosecurity::logger logger;
    std::vector<falcosecurity::metric> m_metrics;

    // table handle through api
    falcosecurity::table m_plugin_table;
    falcosecurity::table_field m_plugin_table_field;
    // my actual table
    my_table m_table;
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_EVENT_PARSING(my_plugin);
FALCOSECURITY_PLUGIN_CAPTURE_LISTENING(my_plugin);
