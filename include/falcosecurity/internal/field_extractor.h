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
    /**
     * @brief Class interface representing a plugin with field
     * extraction capability
     */
    class field_extractor: virtual public plugin
    {
    public:
        /**
         * @brief Represents a single field entry that a plugin with
         * field extraction capability can expose
         */
        struct field
        {
            /**
             * @brief Describes the argument of a single field entry that
             * an plugin with field extraction capability can expose
             */
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

            /**
             * @brief Returns a string representing the given
             * ss_plugin_field_type
             */
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

        field_extractor() = default;

        virtual ~field_extractor() = default;

        /**
         * @brief Returns a list of event sources with which this plugin
         * is compatible for the field extraction capability. An empty list
         * is interpreted by the framework as the plugin being compatible with
         * all event sources.
         * 
         * Overriding this method is optional. It is not pure-virtual, and a
         * default implementation returning an empty list.
         * 
         * @return const std::vector<std::string>& The list of event sources
         */
        virtual void extract_event_sources(std::vector<std::string>& out) const
        {
            out.clear();
        }

        /**
         * @brief Return the list of extractor fields exported by this plugin.
         */
        virtual void fields(std::vector<field>& out) const = 0;

        /**
         * @brief Extracts a field from the given event data. This is meant to
         * be used in plugin_extract_fields() to extract the value of a single
         * field.
         * 
         * @param evt The event data
         * @param field The field extraction request, used for both
         * input and output
         * @return true if the extraction was successful
         * @return false if the extract failed. The failure error must
         * be retrievable by invoking last_error()
         */
        virtual bool extract(const ss_plugin_event* evt, ss_plugin_extract_field* field) = 0;
    };
};