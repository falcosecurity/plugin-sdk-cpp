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
    ss_plugin_rc next(const falcosecurity::event_sourcer* p, ss_plugin_event* evt) override;
    
private:
    uint64_t m_count = 0;
};

class full_plugin:
        public falcosecurity::field_extractor,
        public falcosecurity::event_sourcer
{
public:
    void info(falcosecurity::plugin::information&) const override;
    bool init(const std::string& config) override;
    void last_error(std::string& out) const override;

    void fields(std::vector<field>& out) const override;
    bool extract(const ss_plugin_event* evt, ss_plugin_extract_field* field) override;

    uint32_t id() const;
    void event_source(std::string& out) const;
    std::unique_ptr<falcosecurity::event_sourcer::instance> open(const std::string& params) override;
};
