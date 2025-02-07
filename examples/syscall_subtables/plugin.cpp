// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

    std::string get_name() { return "syscall-subtables-example"; }

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

    bool init(falcosecurity::init_input& i)
    {
        using st = falcosecurity::state_value_type;
        auto& t = i.tables();

        // get the threads table
        m_threads_table = t.get_table("threads", st::SS_PLUGIN_ST_INT64);

        // get the 'file_descriptors' field accessor from the thread table
        m_threads_field_file_descriptor = m_threads_table.get_field(
                t.fields(), "file_descriptors", st::SS_PLUGIN_ST_TABLE);

        // get the 'args' field accessor from the thread table
        m_threads_field_args = m_threads_table.get_field(
                t.fields(), "args", st::SS_PLUGIN_ST_TABLE);

        // get the 'name' field accessor from the fd table
        m_file_descriptor_field_name = t.get_subtable_field(
                m_threads_table, m_threads_field_file_descriptor, "name",
                st::SS_PLUGIN_ST_STRING);

        // get the 'value' field accessor from the args table
        m_args_field =
                t.get_subtable_field(m_threads_table, m_threads_field_args,
                                     "value", st::SS_PLUGIN_ST_STRING);

        // get the 'cgroups' field accessor from the cgroups table
        m_cgroups_table = m_threads_table.get_field(t.fields(), "cgroups",
                                                    st::SS_PLUGIN_ST_TABLE);
        m_cgroups_table_field_name =
                t.get_subtable_field(m_threads_table, m_cgroups_table, "first",
                                     st::SS_PLUGIN_ST_STRING);
        m_cgroups_table_field_value =
                t.get_subtable_field(m_threads_table, m_cgroups_table, "second",
                                     st::SS_PLUGIN_ST_STRING);

        return true;
    }

    bool parse_event(const falcosecurity::parse_event_input& in)
    {
        using st = falcosecurity::state_value_type;

        auto& evt = in.get_event_reader();
        if(evt_type_is_open(evt.get_type()))
        {
            auto& tr = in.get_table_reader();

            auto tid = (int64_t)evt.get_tid();

            // get a thread entry from the thread table
            auto thread_entry = m_threads_table.get_entry(tr, tid);

            // get the args of the thread
            auto args_table = m_threads_table.get_subtable(
                    tr, m_threads_field_args, thread_entry,
                    st::SS_PLUGIN_ST_INT64);

            // iterate all the entries in the args table
            std::printf("\nListing args for TID %ld \n", tid);
            args_table.iterate_entries(
                    tr,
                    [this, tr](const falcosecurity::table_entry& e)
                    {
                        // read the arg field from the current entry of args
                        // table
                        std::string arg;
                        m_args_field.read_value(tr, e, arg);

                        if(!arg.empty())
                        {
                            std::printf("ARG: %s \n", arg.c_str());
                        }

                        return true;
                    });

            // get the fd table of the thread
            auto fd_table = m_threads_table.get_subtable(
                    tr, m_threads_field_file_descriptor, thread_entry,
                    st::SS_PLUGIN_ST_INT64);

            // iterate all the entries in the fd table
            std::printf("\nListing fd names for TID %ld \n", tid);
            fd_table.iterate_entries(
                    tr,
                    [this, tr](const falcosecurity::table_entry& e)
                    {
                        // read the name field from the current entry of the fd
                        // table
                        std::string name;
                        m_file_descriptor_field_name.read_value(tr, e, name);

                        if(!name.empty())
                        {
                            std::printf("NAME: %s \n", name.c_str());
                        }

                        return true;
                    });

            // get the cgroups table of the thread
            auto cgroups_table = m_threads_table.get_subtable(
                    tr, m_cgroups_table, thread_entry, st::SS_PLUGIN_ST_INT64);

            // iterate all the entries in the cgroup table
            std::printf("\nListing cgroups for TID %ld \n", tid);
            cgroups_table.iterate_entries(
                    tr,
                    [this, tr](const falcosecurity::table_entry& e)
                    {
                        std::string cgroup_name;
                        m_cgroups_table_field_name.read_value(tr, e,
                                                              cgroup_name);
                        std::string cgroup_value;
                        m_cgroups_table_field_value.read_value(tr, e,
                                                               cgroup_value);

                        if(!cgroup_name.empty() && !cgroup_value.empty())
                        {
                            std::printf("CGROUP NAME: %s  - CGROUP VALUE: %s\n",
                                        cgroup_name.c_str(),
                                        cgroup_value.c_str());
                        }

                        return true;
                    });
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

    falcosecurity::table_field m_threads_field_file_descriptor;
    falcosecurity::table_field m_threads_field_args;

    falcosecurity::table_field m_file_descriptor_field_name;
    falcosecurity::table_field m_args_field;

    falcosecurity::table_field m_cgroups_table;
    falcosecurity::table_field m_cgroups_table_field_name;
    falcosecurity::table_field m_cgroups_table_field_value;
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_EVENT_PARSING(my_plugin);
