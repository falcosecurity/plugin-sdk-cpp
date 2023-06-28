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

#include <falcosecurity/internal/conversions.h>
#include <falcosecurity/internal/hacks.h>
#include <falcosecurity/types.h>

namespace falcosecurity
{

struct table_info
{
    FALCOSECURITY_INLINE
    table_info(state_value_type t, const std::string& n): key_type(t), name(n)
    {
    }
    FALCOSECURITY_INLINE
    table_info(table_info&&) = default;
    FALCOSECURITY_INLINE
    table_info& operator=(table_info&&) = default;
    FALCOSECURITY_INLINE
    table_info(const table_info&) = default;
    FALCOSECURITY_INLINE
    table_info& operator=(const table_info&) = default;

    state_value_type key_type;
    std::string name;
};

struct table_field_info
{
    FALCOSECURITY_INLINE
    table_field_info(state_value_type t, const std::string& n, bool r):
            field_type(t), name(n), read_only(r)
    {
    }
    FALCOSECURITY_INLINE
    table_field_info(table_field_info&&) = default;
    FALCOSECURITY_INLINE
    table_field_info& operator=(table_field_info&&) = default;
    FALCOSECURITY_INLINE
    table_field_info(const table_field_info&) = default;
    FALCOSECURITY_INLINE
    table_field_info& operator=(const table_field_info&) = default;

    state_value_type field_type;
    std::string name;
    bool read_only;
};

class table_fields
{
    public:
    FALCOSECURITY_INLINE
    table_fields(const _internal::ss_plugin_table_fields_vtable* f,
                 _internal::ss_plugin_owner_t* o,
                 const char* (*glerr)(_internal::ss_plugin_owner_t* o)):
            m_fields(f),
            m_owner(o), m_get_owner_last_error(glerr)
    {
    }
    FALCOSECURITY_INLINE
    table_fields(table_fields&&) = default;
    FALCOSECURITY_INLINE
    table_fields& operator=(table_fields&&) = default;
    FALCOSECURITY_INLINE
    table_fields(const table_fields&) = default;
    FALCOSECURITY_INLINE
    table_fields& operator=(const table_fields&) = default;

    private:
    const _internal::ss_plugin_table_fields_vtable* m_fields;
    _internal::ss_plugin_owner_t* m_owner;
    const char* (*m_get_owner_last_error)(_internal::ss_plugin_owner_t* o);

    friend class table;
    friend class table_init_input;
};

class table_reader
{
    public:
    FALCOSECURITY_INLINE
    table_reader(const _internal::ss_plugin_table_reader_vtable* r,
                 _internal::ss_plugin_owner_t* o,
                 const char* (*glerr)(_internal::ss_plugin_owner_t* o)):
            m_reader(r),
            m_owner(o), m_get_owner_last_error(glerr)
    {
    }
    FALCOSECURITY_INLINE
    table_reader(table_reader&&) = default;
    FALCOSECURITY_INLINE
    table_reader& operator=(table_reader&&) = default;
    FALCOSECURITY_INLINE
    table_reader(const table_reader&) = default;
    FALCOSECURITY_INLINE
    table_reader& operator=(const table_reader&) = default;

    private:
    const _internal::ss_plugin_table_reader_vtable* m_reader;
    _internal::ss_plugin_owner_t* m_owner;
    const char* (*m_get_owner_last_error)(_internal::ss_plugin_owner_t* o);

    friend class table;
    friend class table_field;
};

class table_writer
{
    public:
    FALCOSECURITY_INLINE
    table_writer(const _internal::ss_plugin_table_writer_vtable* w,
                 _internal::ss_plugin_owner_t* o,
                 const char* (*glerr)(_internal::ss_plugin_owner_t* o)):
            m_writer(w),
            m_owner(o), m_get_owner_last_error(glerr)
    {
    }
    FALCOSECURITY_INLINE
    table_writer(table_writer&&) = default;
    FALCOSECURITY_INLINE
    table_writer& operator=(table_writer&&) = default;
    FALCOSECURITY_INLINE
    table_writer(const table_writer&) = default;
    FALCOSECURITY_INLINE
    table_writer& operator=(const table_writer&) = default;

    private:
    const _internal::ss_plugin_table_writer_vtable* m_writer;
    _internal::ss_plugin_owner_t* m_owner;
    const char* (*m_get_owner_last_error)(_internal::ss_plugin_owner_t* o);

    friend class table;
    friend class table_stale_entry;
    friend class table_field;
};

using table_entry = _internal::ss_plugin_table_field_t*;

class table_stale_entry
{
    FALCOSECURITY_INLINE
    table_stale_entry(table_stale_entry&&) = default;
    FALCOSECURITY_INLINE
    table_stale_entry& operator=(table_stale_entry&&) = default;
    FALCOSECURITY_INLINE
    table_stale_entry(const table_stale_entry&) = delete;
    FALCOSECURITY_INLINE
    table_stale_entry& operator=(const table_stale_entry&) = delete;
    FALCOSECURITY_INLINE
    ~table_stale_entry()
    {
        if(m_entry)
        {
            m_writer->m_writer->destroy_table_entry(m_table, m_entry);
        }
    }

    private:
    FALCOSECURITY_INLINE
    table_stale_entry(table_entry e, _internal::ss_plugin_table_t* t,
                      const table_writer& w):
            m_entry(e),
            m_table(t), m_writer(&w)
    {
    }

    table_entry m_entry;
    _internal::ss_plugin_table_t* m_table;
    const table_writer* m_writer;

    friend class table;
};

class table_field
{
    public:
    FALCOSECURITY_INLINE
    table_field():
            table_field("", _internal::ss_plugin_state_type::SS_PLUGIN_ST_INT8,
                        NULL, NULL)
    {
    }
    FALCOSECURITY_INLINE
    table_field(const std::string& n, _internal::ss_plugin_state_type ft,
                _internal::ss_plugin_table_t* t,
                _internal::ss_plugin_table_field_t* f):
            m_name(n),
            m_field_type(ft), m_table(t), m_field(f)
    {
    }
    FALCOSECURITY_INLINE
    table_field(table_field&&) = default;
    FALCOSECURITY_INLINE
    table_field& operator=(table_field&&) = default;
    FALCOSECURITY_INLINE
    table_field(const table_field&) = default;
    FALCOSECURITY_INLINE
    table_field& operator=(const table_field&) = default;

    FALCOSECURITY_INLINE
    const std::string& get_name() { return m_name; }

    FALCOSECURITY_INLINE
    state_value_type get_field_type()
    {
        return static_cast<state_value_type>(m_field_type);
    }

    template<typename T>
    FALCOSECURITY_INLINE void read_value(const table_reader& r, table_entry e,
                                         T& out)
    {
        check_type(out);
        auto res = r.m_reader->read_entry_field(m_table, e, m_field, &m_data);
        if(res != result_code::SS_PLUGIN_SUCCESS)
        {
            std::string msg = "can't read table field at entry";
            auto err = r.m_get_owner_last_error(r.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        _internal::read_state_data<T>(m_data, out);
    }

    template<typename T>
    FALCOSECURITY_INLINE void write_value(const table_writer& w, table_entry e,
                                          const T& in)
    {
        check_type(in);
        _internal::write_state_data<T>(m_data, in);
        auto res = w.m_writer->write_entry_field(m_table, e, m_field, &m_data);
        if(res != result_code::SS_PLUGIN_SUCCESS)
        {
            std::string msg = "can't write table field at entry";
            auto err = w.m_get_owner_last_error(w.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
    }

    private:
    template<typename T> FALCOSECURITY_INLINE void check_type(const T& v) const
    {
        FALCOSECURITY_ASSERT(
                m_field_type == _internal::state_type_of(v),
                "invalid value used to read/write table field: expected "
                "type " +
                        falcosecurity::to_string(
                                (falcosecurity::state_value_type)m_field_type));
    }

    std::string m_name;
    _internal::ss_plugin_state_type m_field_type;
    _internal::ss_plugin_table_t* m_table;
    _internal::ss_plugin_table_field_t* m_field;
    _internal::ss_plugin_state_data m_data;
};

class table
{
    public:
    FALCOSECURITY_INLINE
    table(): table("", _internal::ss_plugin_state_type::SS_PLUGIN_ST_INT8, NULL)
    {
    }
    FALCOSECURITY_INLINE
    table(const std::string& n, _internal::ss_plugin_state_type kt,
          _internal::ss_plugin_table_t* t):
            m_name(n),
            m_key_type(kt), m_table(t), m_data()
    {
    }
    FALCOSECURITY_INLINE
    table(table&&) = default;
    FALCOSECURITY_INLINE
    table& operator=(table&&) = default;
    FALCOSECURITY_INLINE
    table(const table&) = default;
    FALCOSECURITY_INLINE
    table& operator=(const table&) = default;

    FALCOSECURITY_INLINE
    state_value_type get_key_type()
    {
        return static_cast<state_value_type>(m_key_type);
    }

    FALCOSECURITY_INLINE
    std::vector<table_field_info> list_fields(const table_fields& f)
    {
        uint32_t size = 0;
        auto res = f.m_fields->list_table_fields(m_table, &size);
        if(!res)
        {
            std::string msg = "can't list table fields";
            auto err = f.m_get_owner_last_error(f.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        std::vector<table_field_info> infos;
        for(uint32_t i = 0; i < size; i++)
        {
            infos.push_back(table_field_info(res[i].field_type, res[i].name,
                                             res[i].read_only));
        }
        return infos;
    }

    FALCOSECURITY_INLINE
    table_field get_field(const table_fields& f, const std::string& name,
                          state_value_type t)
    {
        auto res = f.m_fields->get_table_field(
                m_table, name.c_str(),
                static_cast<_internal::ss_plugin_state_type>(t));
        if(!res)
        {
            std::string msg = "can't get field";
            auto err = f.m_get_owner_last_error(f.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        return table_field(name,
                           static_cast<_internal::ss_plugin_state_type>(t),
                           m_table, res);
    }

    FALCOSECURITY_INLINE
    table_field add_field(const table_fields& f, const std::string& name,
                          state_value_type t)
    {
        auto res = f.m_fields->add_table_field(
                m_table, name.c_str(),
                static_cast<_internal::ss_plugin_state_type>(t));
        if(!res)
        {
            std::string msg = "can't add field";
            auto err = f.m_get_owner_last_error(f.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        return table_field(name,
                           static_cast<_internal::ss_plugin_state_type>(t),
                           m_table, res);
    }

    FALCOSECURITY_INLINE
    const std::string& get_name() { return m_name; }

    FALCOSECURITY_INLINE
    const std::string& get_name(const table_reader& r)
    {
        auto res = r.m_reader->get_table_name(m_table);
        if(!res)
        {
            std::string msg = "can't get table name";
            auto err = r.m_get_owner_last_error(r.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        m_name.assign(res);
        return m_name;
    }

    FALCOSECURITY_INLINE
    uint64_t get_size(const table_reader& r)
    {
        return r.m_reader->get_table_size(m_table);
    }

    template<typename T>
    FALCOSECURITY_INLINE table_entry get_entry(const table_reader& r,
                                               const T& key)
    {
        check_type(key);
        _internal::write_state_data<T>(m_data, key);
        auto res = static_cast<table_entry>(
                r.m_reader->get_table_entry(m_table, &m_data));
        if(!res)
        {
            std::string msg = "can't get table entry";
            auto err = r.m_get_owner_last_error(r.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        return res;
    }

    FALCOSECURITY_INLINE
    void clear(const table_writer& w)
    {
        auto res = w.m_writer->clear_table(m_table);
        if(res != result_code::SS_PLUGIN_SUCCESS)
        {
            std::string msg = "can't clear table";
            auto err = w.m_get_owner_last_error(w.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
    }

    template<typename T>
    FALCOSECURITY_INLINE void erase_entry(const table_writer& w, const T& key)
    {
        check_type(key);
        _internal::write_state_data<T>(m_data, key);
        auto res = w.m_writer->erase_table_entry(m_table, &m_data);
        if(res != result_code::SS_PLUGIN_SUCCESS)
        {
            std::string msg = "can't erase table entry";
            auto err = w.m_get_owner_last_error(w.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
    }

    FALCOSECURITY_INLINE
    table_stale_entry create_entry(const table_writer& w)
    {
        auto res = w.m_writer->create_table_entry(m_table);
        if(!res)
        {
            std::string msg = "can't create table entry";
            auto err = w.m_get_owner_last_error(w.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        return std::move(table_stale_entry(res, m_table, w));
    }

    template<typename T>
    FALCOSECURITY_INLINE table_entry add_entry(const table_writer& w,
                                               const T& key,
                                               table_stale_entry&& e)
    {
        check_type(key);
        _internal::read_state_data<T>(m_data, key);
        auto res = static_cast<table_entry>(
                w.m_writer->add_table_entry(m_table, &m_data, e.m_entry));
        if(!res)
        {
            std::string msg = "can't add table entry";
            auto err = w.m_get_owner_last_error(w.m_owner);
            if(err)
            {
                msg += ": ";
                msg += err;
            }
            throw plugin_exception(msg);
        }
        e.m_entry = NULL;
        return res;
    }

    private:
    template<typename T> FALCOSECURITY_INLINE void check_type(const T& v) const
    {
        FALCOSECURITY_ASSERT(
                m_key_type == _internal::state_type_of(v),
                "invalid key used for table operation: expected "
                "type " +
                        falcosecurity::to_string(
                                (falcosecurity::state_value_type)m_key_type));
    }
    std::string m_name;
    _internal::ss_plugin_state_type m_key_type;
    _internal::ss_plugin_table_t* m_table;
    _internal::ss_plugin_state_data m_data;
};

}; // namespace falcosecurity
