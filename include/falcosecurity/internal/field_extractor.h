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

#include <vector>
#include "plugin.h"

namespace falcosecurity
{
    class field_extractor: virtual public plugin
    {
    public:
        struct field
        {
            struct argument
            {
                bool key = false;
                bool index = false;
                bool required = false;
            };

            std::string name;
            ss_plugin_field_type type;
            std::string display;
            std::string description;
            argument arg;
            bool list = false;
            std::vector<std::string> properties;

            inline static std::string type_as_string(ss_plugin_field_type t)
            {
                switch (t)
                {
                    case FTYPE_UINT64:
                        return "uint64";
                    case FTYPE_STRING:
                        return "string";
                    default:
                        return "";
                }
            }
        };

        field_extractor()  = default;

        virtual ~field_extractor() = default;

        virtual const std::vector<std::string>& extract_event_sources() const  = 0;

        virtual const std::vector<field>& fields() const  = 0;

        virtual bool extract(const ss_plugin_event* evt, ss_plugin_extract_field* field)  = 0;
    };
};