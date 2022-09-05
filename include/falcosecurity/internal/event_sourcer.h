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
    class event_sourcer: virtual public plugin
    {
    public:
        class instance
        {
        public:
            instance()  = default;

            virtual ~instance() = default;

            virtual ss_plugin_rc next(const event_sourcer* p, ss_plugin_event* evt)  = 0;

            virtual void close()  { }

            virtual const std::string& get_progress(const event_sourcer* p, uint32_t* progress_pct) 
            {
                *progress_pct = 0;
                return s_empty_str;
            }

        private:
            const std::string s_empty_str;
        };

        struct open_param
        {
            std::string value;
            std::string description;
            std::string separator;
        };

        event_sourcer()  { }

        virtual ~event_sourcer() = default;

        virtual uint32_t id() const  = 0;

        virtual const std::string& event_source() const  = 0;

        virtual bool open_param_list(std::vector<open_param>& list) 
        {
            list.clear();
            return true;
        }

        virtual const std::string& event_as_string(const ss_plugin_event *evt) 
        {
            return s_empty_str;
        }

        virtual std::unique_ptr<instance> open(const std::string& params)  = 0;

    private:
        const std::string s_empty_str;
        const std::vector<open_param> s_no_open_params;
    };
};
