/*
Copyright (C) 2022 The Falco Authors.

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

#include "full.h"

full_plugin::full_plugin(): m_info()
{
    m_evt_source = "example";
    m_info.name = "full";
    m_info.description = "Sample of full plugin";
    m_info.contact = "https://github.com/falcosecurity/plugins";
    m_info.version = "0.1.0";
    
    falcosecurity::field_extractor::field f;
    f.name = "example.count";
    f.type = FTYPE_UINT64;
    f.description = "some desc";
    f.display = "some display";
    m_fields.push_back(f);
}

const falcosecurity::plugin::information& full_plugin::info() const 
{
    return m_info;
}

bool full_plugin::init(const std::string& config) 
{
    return true;
}

const std::string& full_plugin::last_error() const 
{
    return m_last_error;
}

const std::vector<std::string>& full_plugin::extract_event_sources() const 
{
    return m_extract_event_sources;
}

const std::vector<falcosecurity::field_extractor::field>& full_plugin::fields() const 
{
    return m_fields;
}

bool full_plugin::extract(const ss_plugin_event* evt, ss_plugin_extract_field* field) 
{
    field->res.u64 = (uint64_t*) evt->data;
    field->res_len = 1;
    return true;
}

uint32_t full_plugin::id() const 
{
    return 999;
}

const std::string& full_plugin::event_source() const 
{
    return m_evt_source;
}

std::unique_ptr<falcosecurity::event_sourcer::instance> full_plugin::open(const std::string& params) 
{
    return std::unique_ptr<falcosecurity::event_sourcer::instance>(new full_instance);
}

ss_plugin_rc full_instance::next(const falcosecurity::event_sourcer* p, ss_plugin_event* evt) 
{
    m_count++;
    evt->data = (uint8_t*) &m_count;
    evt->datalen = sizeof(uint64_t);
    return SS_PLUGIN_SUCCESS;
}
