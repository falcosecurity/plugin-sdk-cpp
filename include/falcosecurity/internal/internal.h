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
            std::string m_get_progress_str;
        };

        struct plugin_wrapper
        {
            plugin_wrapper(std::unique_ptr<plugin> p)
                : m_plugin(std::move(p)) { }

            ~plugin_wrapper()
            {
                m_plugin.release();
            }

            std::unique_ptr<plugin> m_plugin;
            std::string m_last_err;
            std::string m_init_schema;
            ss_plugin_schema_type m_init_schema_type;
            falcosecurity::plugin::information m_info;
            
            // event sourcing capability state
            event_sourcer* m_event_sourcer;
            std::string m_event_source;
            std::string m_event_to_string;
            std::string m_open_param_list_str;
            std::vector<event_sourcer::open_param> m_open_param_list;

            // field extraction capability state
            field_extractor* m_field_extractor;
            std::vector<std::string> m_extract_event_sources;
            std::vector<falcosecurity::field_extractor::field> m_fields;
        };

        inline static plugin_wrapper* allocate() noexcept
        {
            auto p = new plugin_wrapper(factory());
#ifdef _DEBUG
            if (!p->m_plugin)
            {
                perror("broken plugin factory function: can't return nullptr");
                exit(1);
            }
#endif
            p->m_plugin->info(p->m_info);
            p->m_plugin->init_schema(p->m_init_schema_type, p->m_init_schema);

            p->m_event_sourcer = dynamic_cast<falcosecurity::event_sourcer*>(p->m_plugin.get());
            if (p->m_event_sourcer)
            {
                p->m_event_sourcer->event_source(p->m_event_source);
            }

            p->m_field_extractor = dynamic_cast<falcosecurity::field_extractor*>(p->m_plugin.get());
            if (p->m_field_extractor)
            {
                p->m_field_extractor->fields(p->m_fields);
                p->m_field_extractor->extract_event_sources(p->m_extract_event_sources);
            }
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
