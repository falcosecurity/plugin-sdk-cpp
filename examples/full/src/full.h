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

#pragma once

#include <falcosecurity/sdk.h>

class full_instance: public falcosecurity::event_sourcer::instance
{
public:
    ss_plugin_rc next(const falcosecurity::event_sourcer* p, ss_plugin_event* evt);
    
private:
    uint64_t m_count = 0;
};

class full_plugin:
        public falcosecurity::field_extractor,
        public falcosecurity::event_sourcer
{
public:
    full_plugin();

    const falcosecurity::plugin::information& info() const  override;
    bool init(const std::string& config)  override;
    const std::string& last_error() const  override;

    const std::vector<std::string>& extract_event_sources() const  override;
    const std::vector<field>& fields() const  override;
    bool extract(const ss_plugin_event* evt, ss_plugin_extract_field* field)  override;

    uint32_t id() const;
    const std::string& event_source() const;
    std::unique_ptr<falcosecurity::event_sourcer::instance> open(const std::string& params);

private:
    falcosecurity::plugin::information m_info;
    std::string m_evt_source;
    std::string m_last_error;
    std::vector<std::string> m_extract_event_sources;
    std::vector<falcosecurity::field_extractor::field> m_fields;
};
