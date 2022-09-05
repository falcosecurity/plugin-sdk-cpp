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
    /**
     * @brief Class interface representing a Falcosecurity plugin
     */
    class plugin
    {
    public:
        /**
         * @brief A struct containing the general information about a plugin
         */
        struct information
        {
            std::string name;
            std::string description;
            std::string contact;
            std::string version;
            std::string required_api_version = PLUGIN_API_VERSION_STR;
        };

        plugin() = default;

        virtual ~plugin() = default;

        /**
         * @brief Returns a pointer to a struct containing all the general
         * information about this plugin.
         */
        virtual void info(plugin::information& out) const = 0;

        /**
         * @brief Initializes this plugin with a given config string
         * 
         * @param config A string representing the plugin init configuration
         * @return true if the initialization was successful
         * @return false if the initialization failed. The failure error must
         * be retrievable by invoking last_error() 
         */
        virtual bool init(const std::string& config) = 0;

        /**
         * @brief Returns the last error occurred in the plugin.
         */
        virtual void last_error(std::string& out) const = 0;

        /**
         * @brief Returns the init configuration schema for this plugin.
         * This is meant to be used in plugin_get_init_schema() to return a
         * schema describing the data expected to be passed as a configuration
         * during the plugin initialization. So far, the only supported schema
         * type is the JSON Schema specific: https://json-schema.org/.
         * An empty string or a SS_PLUGIN_SCHEMA_NONE schema_type are
         * interpreted as the absence of a schema, and the init configuration
         * will not be pre-validated by the framework.
         * 
         * If JSON Schema is returned, the init configuration will be expected
         * to be a json-formatted string. If so, the init() function can assume
         * the configuration to be well-formed according to the returned schema,
         * as the framework will perform a pre-validation before initializing
         * the plugin.
         * 
         * Overriding this method is optional. It is not pure-virtual, and a
         * default implementation returning no schema is provided.
         * 
         * @param schema_type Set as output with the ss_plugin_schema_type value
         * describing the type of the returned schema
         * @return const std::string& String representing the init config schema
         */
        virtual void init_schema(ss_plugin_schema_type& schema_type, std::string& schema) const 
        {
            schema_type = SS_PLUGIN_SCHEMA_NONE;
            schema = "";
        }
    };
};
