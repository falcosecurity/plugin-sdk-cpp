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
     * @brief Class interface representing a plugin with 
     * event sourcing capability
     */
    class event_sourcer: virtual public plugin
    {
    public:
        /**
         * @brief Represents an event source capture session instance
         * returned by a call to open of a plugin with event sourcing capability
         * implementing the event_sourcer interface
         */
        class instance
        {
        public:
            instance() = default;

            virtual ~instance() = default;
            
            /**
             * @brief Fetches the next event of the event source.
             * This is meant to be used in plugin_next_batch() to source a new
             * event.
             * 
             * This can set a timestamp in the new event. If not set manually, 
             * the framework will set a timestamp automatically. This must be
             * consistent in setting timestamps: either it sets it for every
             * event, or for none.
             * 
             * @param p Pointer to the plugin that opened this instance
             * @param evt Pointer used as output to write the new event data
             * @return SS_PLUGIN_SUCCESS if the event was generated successfully
             * @return SS_PLUGIN_FAILURE if there was a failure. The failure
             * error must be retrievable by invoking last_error().
             * @return SS_PLUGIN_TIMEOUT if no new event is currently available,
             * but could be in the next invocation of next().
             * @return SS_PLUGIN_EOF if no new event is available in the event
             * source. Once SS_PLUGIN_EOF is returned, next() must keep
             * returning SS_PLUGIN_EOF if invoked again.
             */
            virtual ss_plugin_rc next(const event_sourcer* p, ss_plugin_event* evt) = 0;
            
            /**
             * @brief Returns a float64 representing the normalized progress
             * percentage such that 0 <= percentage <= 1, and a string
             * representation of the same percentage value. This is meant to be
             * used in plugin_get_progress() to optionally notify the framework
             * about the current event generation progress of this event source.
             * The instance is the owner of the returned string reference.
             * 
             * @param p Pointer to the plugin that opened this instance
             * @param progress_pct Output pointer used to write the percentage
             * @return const std::string& String representing the formatted
             * percentage.
             */
            virtual const std::string& get_progress(const event_sourcer* p, double* progress_pct)
            {
                *progress_pct = 0.0;
                return s_empty_str;
            }

        private:
            const std::string s_empty_str;
        };

        /**
         * @brief Represents a valid parameter for open()
         */
        struct open_param
        {
            std::string value;
            std::string description;
            std::string separator;
        };

        event_sourcer() = default;

        virtual ~event_sourcer() = default;

        /**
         * @brief Returns the event ID allocated to your plugin.
         * During development and before receiving an official event ID, you
         * can use the "test" value of 999.
         */
        virtual uint32_t id() const = 0;

        /**
         * @brief Returns the name of the event source implemented by this
         * plugin for its event sourcing capability. The plugin is the owner 
         * of the returned string reference.
         */
        virtual const std::string& event_source() const = 0;
        
        /**
         * @brief Returns a list of suggested open parameters. This is meant
         * to be used in plugin_list_open_params() to return a list of suggested
         * parameters that would be accepted as valid arguments for open().
         * 
         * Overriding this method is optional. It is not pure-virtual, and a
         * default implementation returning an empty list.
         * 
         * @param list Container used as output for the open param values
         * @return true If the param list retrieval was successful
         * @return false If the param list retrieval failed. The failure error
         * must be retrievable by invoking last_error()
         */
        virtual bool open_param_list(std::vector<open_param>& list)
        {
            list.clear();
            return true;
        }
        
        /**
         * @brief Returns the name of the event source implemented by this
         * plugin for its event sourcing capability. The plugin is the owner 
         * of the returned string reference.
         */
        virtual const std::string& event_as_string(const ss_plugin_event *evt)
        {
            return s_empty_str;
        }

        /**
         * @brief Opens the source and starts a capture (e.g. stream of events).
         * The argument string represents the user-defined parameter and can
         * be used to customize how the source is opened. The return value is
         * an user-defined object representing the source capture session.
         * Multiple instances can be opened for the same plugin.
         * 
         * @param params String representing the open parameter
         * @return std::unique_ptr<instance> The opened event stream instance.
         * @return nullptr if there was a failure. The failure error must
         * be retrievable by invoking last_error()
         */
        virtual std::unique_ptr<instance> open(const std::string& params) = 0;

    private:
        const std::string s_empty_str;
        const std::vector<open_param> s_no_open_params;
    };
};
