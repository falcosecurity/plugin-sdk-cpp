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

#pragma once

#include <falcosecurity/internal/conversions.h>
#include <falcosecurity/internal/hacks.h>
#include <falcosecurity/types.h>
#include <falcosecurity/inputs.h>

namespace falcosecurity
{

using plugin_table_entry = _internal::ss_plugin_table_entry_t;

using plugin_table_field = _internal::ss_plugin_table_field_t;

using plugin_state_data = _internal::ss_plugin_state_data;

using table_input = _internal::ss_plugin_table_input;

template<typename Table, typename KeyType> class plugin_table
{
    public:
    plugin_table(): m_table_input(), m_fields() {}

    const table_input& get_table_input()
    {
        m_table_input = table_input{};

        m_table_input.table = this;

        m_table_input.name = get_name(this);
        m_table_input.key_type = get_key_type(this);

        m_table_input.fields_ext = &this->fields_vtable;
        m_table_input.writer_ext = &this->writer_vtable;
        m_table_input.reader_ext = &this->reader_vtable;

        m_table_input.fields_ext->list_table_fields = list_fields;
        m_table_input.fields_ext->get_table_field = get_field;
        m_table_input.fields_ext->add_table_field = add_field;
        m_table_input.fields.list_table_fields =
                m_table_input.fields_ext->list_table_fields;
        m_table_input.fields.get_table_field =
                m_table_input.fields_ext->get_table_field;
        m_table_input.fields.add_table_field =
                m_table_input.fields_ext->add_table_field;
        m_table_input.reader_ext->get_table_name = get_name;
        m_table_input.reader_ext->get_table_size = get_size;
        m_table_input.reader_ext->get_table_entry = get_entry;
        m_table_input.reader_ext->read_entry_field = read_entry_field;
        m_table_input.reader_ext->release_table_entry = release_table_entry;
        m_table_input.reader_ext->iterate_entries = iterate_entries;
        m_table_input.reader.get_table_name =
                m_table_input.reader_ext->get_table_name;
        m_table_input.reader.get_table_size =
                m_table_input.reader_ext->get_table_size;
        m_table_input.reader.get_table_entry =
                m_table_input.reader_ext->get_table_entry;
        m_table_input.reader.read_entry_field =
                m_table_input.reader_ext->read_entry_field;
        m_table_input.writer_ext->clear_table = clear;
        m_table_input.writer_ext->erase_table_entry = erase_entry;
        m_table_input.writer_ext->create_table_entry = create_entry;
        m_table_input.writer_ext->destroy_table_entry = destroy_entry;
        m_table_input.writer_ext->add_table_entry = add_entry;
        m_table_input.writer_ext->write_entry_field = write_entry_field;
        m_table_input.writer.clear_table =
                m_table_input.writer_ext->clear_table;
        m_table_input.writer.erase_table_entry =
                m_table_input.writer_ext->erase_table_entry;
        m_table_input.writer.create_table_entry =
                m_table_input.writer_ext->create_table_entry;
        m_table_input.writer.destroy_table_entry =
                m_table_input.writer_ext->destroy_table_entry;
        m_table_input.writer.add_table_entry =
                m_table_input.writer_ext->add_table_entry;
        m_table_input.writer.write_entry_field =
                m_table_input.writer_ext->write_entry_field;

        return m_table_input;
    }

    private:
    static const char* get_name(_internal::ss_plugin_table_t* _t)
    {
        auto t = static_cast<Table*>(_t);
        std::string& name = t->get_name();

        return name.c_str();
    }

    static uint64_t get_size(_internal::ss_plugin_table_t* _t)
    {
        auto t = static_cast<Table*>(_t);
        return t->get_size();
    }

    _internal::ss_plugin_state_type
    get_key_type(_internal::ss_plugin_table_t* _t)
    {
        auto t = static_cast<Table*>(_t);
        state_value_type res = t->get_key_type();

        return static_cast<_internal::ss_plugin_state_type>(res);
    }

    static const _internal::ss_plugin_table_fieldinfo*
    list_fields(_internal::ss_plugin_table_t* _t, uint32_t* nfields)
    {
        auto t = static_cast<Table*>(_t);
        std::vector<table_field_info> res = t->list_fields();

        t->m_fields.clear();
        for(auto& i : res)
        {
            _internal::ss_plugin_table_fieldinfo fi = {
                    .name = i.name.c_str(),
                    .field_type = i.field_type,
                    .read_only = i.read_only,
            };
            t->m_fields.push_back(fi);
        }

        *nfields = (uint32_t)t->m_fields.size();
        return t->m_fields.data();
    }

    static _internal::ss_plugin_table_field_t*
    get_field(_internal::ss_plugin_table_t* _t, const char* name,
              _internal::ss_plugin_state_type data_type)
    {
        auto t = static_cast<Table*>(_t);
        plugin_table_field* res = t->get_field(
                std::string(name), static_cast<state_value_type>(data_type));

        return static_cast<_internal::ss_plugin_table_field_t*>(res);
    }

    static _internal::ss_plugin_table_field_t*
    add_field(_internal::ss_plugin_table_t* _t, const char* name,
              _internal::ss_plugin_state_type data_type)
    {
        // TODO
        return nullptr;
    }

    static _internal::ss_plugin_table_entry_t*
    get_entry(_internal::ss_plugin_table_t* _t,
              const _internal::ss_plugin_state_data* key)
    {
        auto t = static_cast<Table*>(_t);

        KeyType k;
        read_state_data(key, k);
        plugin_table_entry* res = t->get_entry(k);

        return static_cast<_internal::ss_plugin_table_field_t*>(res);
    }

    static _internal::ss_plugin_rc
    read_entry_field(_internal::ss_plugin_table_t* _t,
                     _internal::ss_plugin_table_entry_t* _e,
                     const _internal::ss_plugin_table_field_t* _f,
                     _internal::ss_plugin_state_data* out)
    {
        auto t = static_cast<Table*>(_t);

        auto res =
                t->read_entry_field(static_cast<plugin_table_entry*>(_e),
                                    static_cast<const plugin_table_field*>(_f),
                                    static_cast<plugin_state_data*>(out));
        if(res)
        {
            return _internal::SS_PLUGIN_SUCCESS;
        }

        return _internal::SS_PLUGIN_FAILURE;
    }

    static void release_table_entry(_internal::ss_plugin_table_t* _t,
                                    _internal::ss_plugin_table_entry_t* _e)
    {
        // TODO
    }

    static _internal::ss_plugin_bool
    iterate_entries(_internal::ss_plugin_table_t* _t,
                    _internal::ss_plugin_table_iterator_func_t it,
                    _internal::ss_plugin_table_iterator_state_t* s)
    {
        // TODO
        return true;
    }

    static _internal::ss_plugin_rc clear(_internal::ss_plugin_table_t* _t)
    {
        // TODO
        return _internal::SS_PLUGIN_SUCCESS;
    }

    static _internal::ss_plugin_rc
    erase_entry(_internal::ss_plugin_table_t* _t,
                const _internal::ss_plugin_state_data* key)
    {
        // TODO
        return _internal::SS_PLUGIN_SUCCESS;
    }

    static _internal::ss_plugin_table_entry_t*
    create_entry(_internal::ss_plugin_table_t* t)
    {
        // TODO
        return nullptr;
    }

    static void destroy_entry(_internal::ss_plugin_table_t* _t,
                              _internal::ss_plugin_table_entry_t* _e)
    {
        // TODO
    }

    static _internal::ss_plugin_table_entry_t*
    add_entry(_internal::ss_plugin_table_t* _t,
              const _internal::ss_plugin_state_data* key,
              _internal::ss_plugin_table_entry_t* _e)
    {
        // TODO
        return nullptr;
    }

    static _internal::ss_plugin_rc
    write_entry_field(_internal::ss_plugin_table_t* _t,
                      _internal::ss_plugin_table_entry_t* _e,
                      const _internal::ss_plugin_table_field_t* _f,
                      const _internal::ss_plugin_state_data* in)
    {
        // TODO
        return _internal::SS_PLUGIN_SUCCESS;
    }

    table_input m_table_input;

    _internal::ss_plugin_table_reader_vtable_ext reader_vtable;
    _internal::ss_plugin_table_writer_vtable_ext writer_vtable;
    _internal::ss_plugin_table_fields_vtable_ext fields_vtable;

    std::vector<_internal::ss_plugin_table_fieldinfo> m_fields;

    friend class table_init_input;
};

} // namespace falcosecurity