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
#include <falcosecurity/table.h>
#include <falcosecurity/base_table.h>
#include <falcosecurity/types.h>
#include <falcosecurity/event_reader.h>
#include <falcosecurity/extract_request.h>

namespace falcosecurity
{

using table_input = _internal::ss_plugin_table_input;

class table_init_input
{
    public:
    FALCOSECURITY_INLINE
    table_init_input(_internal::ss_plugin_owner_t* o,
                     const _internal::ss_plugin_init_input* i):
            m_owner(o),
            m_input(i),
            m_fielder(i->tables->fields_ext, i->owner, i->get_owner_last_error),
            m_reader(i->tables->reader_ext, i->owner, i->get_owner_last_error),
            m_writer(i->tables->writer_ext, i->owner, i->get_owner_last_error)
    {
    }
    FALCOSECURITY_INLINE
    table_init_input(table_init_input&&) = default;
    FALCOSECURITY_INLINE
    table_init_input& operator=(table_init_input&&) = default;
    FALCOSECURITY_INLINE
    table_init_input(const table_init_input&) = default;
    FALCOSECURITY_INLINE
    table_init_input& operator=(const table_init_input&) = default;

    FALCOSECURITY_INLINE
    table_fields& fields() { return m_fielder; }

    FALCOSECURITY_INLINE
    std::vector<table_info> list_tables()
    {
        uint32_t size = 0;
        auto res = m_input->tables->list_tables(m_owner, &size);
        if(!res)
        {
            std::string msg = "can't list tables";
            auto err = m_fielder.m_get_owner_last_error(m_fielder.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        std::vector<table_info> infos;
        for(uint32_t i = 0; i < size; i++)
        {
            infos.push_back(table_info(res[i].key_type, res[i].name));
        }
        return infos;
    }

    FALCOSECURITY_INLINE
    table get_table(const std::string& name, state_value_type key_type)
    {
        auto res = m_input->tables->get_table(
                m_owner, name.c_str(),
                static_cast<_internal::ss_plugin_state_type>(key_type));
        if(!res)
        {
            std::string msg = "can't get table";
            auto err = m_fielder.m_get_owner_last_error(m_fielder.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        return table(name, key_type, res);
    }

    // todo(jasondellaluce): this is still experimental and we may want to add
    // an ad-hoc wrapper for plugin-owned tables too
    FALCOSECURITY_INLINE
    void add_table(const table_input& in)
    {
        auto res = m_input->tables->add_table(
                m_owner,
                static_cast<const _internal::ss_plugin_table_input*>(&in));
        if(res != _internal::SS_PLUGIN_SUCCESS)
        {
            std::string msg = "can't add table";
            auto err = m_fielder.m_get_owner_last_error(m_fielder.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
    }

    FALCOSECURITY_INLINE
    table_field get_subtable_field(table& main_table, table_field& field,
                                   const std::string& name,
                                   state_value_type key_type)
    {
        auto entry = main_table.create_entry(m_writer);

        _internal::ss_plugin_table_t* subtable_ptr;
        field.read_value(m_reader, entry, subtable_ptr);

        auto subtable =
                table(field.get_name(), field.get_field_type(), subtable_ptr);

        return subtable.get_field(fields(), name, key_type);
    }

    FALCOSECURITY_INLINE
    table_field add_subtable_field(table& main_table, table_field& field,
                                   const std::string& name,
                                   state_value_type key_type)
    {
        auto entry = main_table.create_entry(m_writer);

        _internal::ss_plugin_table_t* subtable_ptr;
        field.read_value(m_reader, entry, subtable_ptr);

        auto subtable =
                table(field.get_name(), field.get_field_type(), subtable_ptr);

        return subtable.add_field(fields(), name, key_type);
    }

    private:
    _internal::ss_plugin_owner_t* m_owner;
    const _internal::ss_plugin_init_input* m_input;
    table_fields m_fielder;
    table_reader m_reader;
    table_writer m_writer;
};

class init_input
{
    public:
    FALCOSECURITY_INLINE
    init_input(const _internal::ss_plugin_init_input* i):
            m_input(i), m_table_input(i->owner, i)
    {
    }
    FALCOSECURITY_INLINE
    init_input(init_input&&) = default;
    FALCOSECURITY_INLINE
    init_input& operator=(init_input&&) = default;
    FALCOSECURITY_INLINE
    init_input(const init_input&) = default;
    FALCOSECURITY_INLINE
    init_input& operator=(const init_input&) = default;

    FALCOSECURITY_INLINE
    std::string get_config() { return std::string(m_input->config); }

    FALCOSECURITY_INLINE
    table_init_input& tables() { return m_table_input; }

    FALCOSECURITY_INLINE
    logger get_logger() const
    {
        return logger(m_input->owner, m_input->log_fn);
    }

    private:
    const _internal::ss_plugin_init_input* m_input;
    table_init_input m_table_input;
};

class parse_event_input
{
    public:
    FALCOSECURITY_INLINE
    parse_event_input(const falcosecurity::event_reader& er,
                      const falcosecurity::table_reader& tr,
                      const falcosecurity::table_writer& tw):
            m_evt_reader(er),
            m_table_reader(tr), m_table_writer(tw)
    {
    }
    FALCOSECURITY_INLINE
    parse_event_input(parse_event_input&&) = default;
    FALCOSECURITY_INLINE
    parse_event_input& operator=(parse_event_input&&) = delete;
    FALCOSECURITY_INLINE
    parse_event_input(const parse_event_input&) = default;
    FALCOSECURITY_INLINE
    parse_event_input& operator=(const parse_event_input&) = delete;

    FALCOSECURITY_INLINE
    const falcosecurity::event_reader& get_event_reader() const
    {
        return m_evt_reader;
    }

    FALCOSECURITY_INLINE
    const falcosecurity::table_reader& get_table_reader() const
    {
        return m_table_reader;
    }

    FALCOSECURITY_INLINE
    const falcosecurity::table_writer& get_table_writer() const
    {
        return m_table_writer;
    }

    private:
    const falcosecurity::event_reader& m_evt_reader;
    const falcosecurity::table_reader& m_table_reader;
    const falcosecurity::table_writer& m_table_writer;
};

class extract_fields_input
{
    public:
    FALCOSECURITY_INLINE
    extract_fields_input(const falcosecurity::event_reader& er,
                         const falcosecurity::table_reader& tr):
            m_evt_reader(er),
            m_table_reader(tr), m_extract_request(nullptr)
    {
    }
    FALCOSECURITY_INLINE
    extract_fields_input(extract_fields_input&&) = default;
    FALCOSECURITY_INLINE
    extract_fields_input& operator=(extract_fields_input&&) = delete;
    FALCOSECURITY_INLINE
    extract_fields_input(const extract_fields_input&) = default;
    FALCOSECURITY_INLINE
    extract_fields_input& operator=(const extract_fields_input&) = delete;

    FALCOSECURITY_INLINE
    const falcosecurity::event_reader& get_event_reader() const
    {
        return m_evt_reader;
    }

    FALCOSECURITY_INLINE
    const falcosecurity::table_reader& get_table_reader() const
    {
        return m_table_reader;
    }

    FALCOSECURITY_INLINE
    falcosecurity::extract_request& get_extract_request() const
    {
        return *m_extract_request;
    }

    FALCOSECURITY_INLINE
    void set_extract_request(falcosecurity::extract_request& e)
    {
        m_extract_request = &e;
    }

    private:
    const falcosecurity::event_reader& m_evt_reader;
    const falcosecurity::table_reader& m_table_reader;
    falcosecurity::extract_request* m_extract_request;
};

class set_config_input
{
    public:
    FALCOSECURITY_INLINE
    set_config_input(const _internal::ss_plugin_set_config_input* i): m_input(i)
    {
    }
    FALCOSECURITY_INLINE
    set_config_input(set_config_input&&) = default;
    FALCOSECURITY_INLINE
    set_config_input& operator=(set_config_input&&) = default;
    FALCOSECURITY_INLINE
    set_config_input(const set_config_input&) = default;
    FALCOSECURITY_INLINE
    set_config_input& operator=(const set_config_input&) = default;

    FALCOSECURITY_INLINE
    std::string get_config() { return std::string(m_input->config); }

    private:
    const _internal::ss_plugin_set_config_input* m_input;
};

class capture_listen_input
{
    public:
    FALCOSECURITY_INLINE
    capture_listen_input(const _internal::ss_plugin_capture_listen_input* i,
                         const falcosecurity::table_reader& tr,
                         const falcosecurity::table_writer& tw):
            m_input(i),
            m_table_reader(tr), m_table_writer(tw)
    {
    }
    FALCOSECURITY_INLINE
    capture_listen_input(capture_listen_input&&) = default;
    FALCOSECURITY_INLINE
    capture_listen_input& operator=(capture_listen_input&&) = default;
    FALCOSECURITY_INLINE
    capture_listen_input(const capture_listen_input&) = default;
    FALCOSECURITY_INLINE
    capture_listen_input& operator=(const capture_listen_input&) = default;

    FALCOSECURITY_INLINE
    const falcosecurity::table_reader& get_table_reader() const
    {
        return m_table_reader;
    }

    FALCOSECURITY_INLINE
    const falcosecurity::table_writer& get_table_writer() const
    {
        return m_table_writer;
    }

    private:
    const _internal::ss_plugin_capture_listen_input* m_input;
    const falcosecurity::table_reader& m_table_reader;
    const falcosecurity::table_writer& m_table_writer;
};

}; // namespace falcosecurity
