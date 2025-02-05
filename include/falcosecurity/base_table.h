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

template<typename T> 
class base_table
{
    public:
    base_table() : m_table_input(), m_fields() {}

    _internal::ss_plugin_table_input& get_table_input()
    {
        m_table_input = _internal::ss_plugin_table_input{};

        m_table_input.table = this;

        m_table_input.name = get_name(this);
        m_table_input.key_type = get_key_type(this);

        m_table_input.fields_ext = &this->fields_vtable;
        m_table_input.writer_ext = &this->writer_vtable;
        m_table_input.reader_ext = &this->reader_vtable;

        m_table_input.fields_ext->list_table_fields = list_fields;

        return m_table_input;
    }

    private:

    static const char* get_name(_internal::ss_plugin_table_t* _t)
    {
        auto t = static_cast<T*>(_t);
        std::string name = t->get_name();

        return name.c_str();
    }

    _internal::ss_plugin_state_type get_key_type(_internal::ss_plugin_table_t* _t)
    {
        auto t = static_cast<T*>(_t);
        return t->get_key_type();
    }

    //std::vector<table_field_info> list_fields();
    static const _internal::ss_plugin_table_fieldinfo* list_fields(_internal::ss_plugin_table_t* _t, uint32_t* nfields) {
		auto t = static_cast<T*>(_t);
        auto infos = t->list_fields();

        t->m_fields.clear();
        for(auto& i : infos)
        {
            _internal::ss_plugin_table_fieldinfo fi = 
            {
                .name = i.name.c_str(),
                .field_type = i.field_type,
                .read_only = i.read_only,
            };
            t->m_fields.push_back(fi);
        }

		*nfields = (uint32_t)t->m_fields.size();
		return t->m_fields.data();
	}

    _internal::ss_plugin_table_input m_table_input;

    _internal::ss_plugin_table_reader_vtable_ext reader_vtable;
	_internal::ss_plugin_table_writer_vtable_ext writer_vtable;
    _internal::ss_plugin_table_fields_vtable_ext fields_vtable;

    std::vector<_internal::ss_plugin_table_fieldinfo> m_fields;
};

} // namespace falcosecurity