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

void full_plugin::info(falcosecurity::plugin::information& out) const 
{
    out.name = "full";
    out.description = "Sample of full plugin";
    out.contact = "https://github.com/falcosecurity/plugins";
    out.version = "0.1.0";
}

bool full_plugin::init(const std::string& config) 
{
    return true;
}

void full_plugin::last_error(std::string& out) const 
{
    out.clear();
}

void full_plugin::fields(std::vector<falcosecurity::field_extractor::field>& out) const 
{
    out = {{"example.count", FTYPE_UINT64,"some display","some desc"}};
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

void full_plugin::event_source(std::string& out) const 
{
    out = "example";
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
