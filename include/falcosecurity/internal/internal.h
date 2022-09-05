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

#include "factory.h"
#include "plugin.h"
#include "event_sourcer.h"
#include "field_extractor.h"

namespace falcosecurity
{
    namespace _internal
    {
        struct instance_wrapper
        {
            std::unique_ptr<event_sourcer::instance> instance;
            ss_plugin_event m_event;
        };

        struct plugin_wrapper
        {
            std::unique_ptr<plugin> m_plugin;
            event_sourcer* m_event_sourcer;
            field_extractor* m_field_extractor;

            std::string m_exception_err;
            std::string m_open_param_list_str;
            std::vector<event_sourcer::open_param> m_open_param_list;
        };

        inline static plugin_wrapper* allocate()
        {
            auto p = new plugin_wrapper();
            p->m_plugin = factory();
#ifdef _DEBUG
            if (!p->m_plugin)
            {
                perror("interface implementation not registered: falcosecurity::plugin");
                exit(1);
            }
#endif
            p->m_event_sourcer = dynamic_cast<falcosecurity::event_sourcer*>(p->m_plugin.get());
            p->m_field_extractor = dynamic_cast<falcosecurity::field_extractor*>(p->m_plugin.get());
            return p;
        }

        inline static void deallocate(plugin_wrapper* p)
        {
            delete p;
        }

        inline static void check_event_sourcer(const plugin_wrapper* p)
        {
#ifdef _DEBUG
            if (!p->m_event_sourcer)
            {
                perror("interface implementation not registered: falcosecurity::event_sourcer");
                exit(1);
            }
#endif
        }

        inline static void check_field_extractor(const plugin_wrapper* p)
        {
#ifdef _DEBUG
            if (!p->m_field_extractor)
            {
                perror("interface implementation not registered: falcosecurity::field_extractor");
                exit(1);
            }
#endif
        }
    };
};
