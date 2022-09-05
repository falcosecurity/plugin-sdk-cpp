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

#include <string>
#include "deps/plugin_api.h"
#include "deps/plugin_types.h"

namespace falcosecurity
{
    class plugin
    {
    public:
        struct information
        {
            std::string name;
            std::string description;
            std::string contact;
            std::string version;
            std::string required_api_version = PLUGIN_API_VERSION_STR;
        };

        plugin()  = default;

        virtual ~plugin() = default;

        virtual const plugin::information& info() const  = 0;

        virtual bool init(const std::string& config)  = 0;

        virtual const std::string& last_error() const  = 0;

        virtual const std::string& init_schema(ss_plugin_schema_type *schema_type) const 
        {
            return s_empty_str;
        }

    private:
        const std::string s_empty_str;
    };
};
