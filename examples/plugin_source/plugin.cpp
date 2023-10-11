// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <falcosecurity/sdk.h>
#include <thread>
#include <atomic>

class my_event_source
{
    public:
    virtual ~my_event_source() = default;

    my_event_source(size_t max_evts): m_count(0), m_max_evts(max_evts), m_enc()
    {
    }

    // (optional)
    // void close() {}

    // (optional)
    double get_progress(std::string& fmt)
    {
        fmt = "0.00%";
        return 0.0;
    }

    falcosecurity::result_code next_event(falcosecurity::event_writer& evt)
    {
        if(m_count >= m_max_evts)
        {
            return falcosecurity::result_code::SS_PLUGIN_EOF;
        }
        auto msg = "hello world #" + std::to_string(m_count++);
        m_enc.set_data((void*)msg.c_str(), msg.size() + 1);
        m_enc.encode(evt);
        return falcosecurity::result_code::SS_PLUGIN_SUCCESS;
    }

    private:
    size_t m_count;
    size_t m_max_evts;
    falcosecurity::events::pluginevent_e_encoder m_enc;
};

class my_plugin
{
    public:
    virtual ~my_plugin() = default;

    std::string get_name() { return "plugin-source-example"; }

    std::string get_version() { return "0.1.0"; }

    std::string get_description() { return "some description"; }

    std::string get_contact() { return "some contact"; }

    uint32_t get_id() { return 999; };

    std::string get_event_source() { return "example"; }

    // (optional)
    std::vector<falcosecurity::open_param> list_open_params() { return {}; }

    // (optional)
    std::string event_to_string(const falcosecurity::event_reader& evt)
    {
        return "evt num: " + std::to_string(evt.get_num());
    }

    // (optional)
    void destroy() {}

    bool init(falcosecurity::init_input& i) { return true; }

    std::unique_ptr<my_event_source> open(const std::string& params)
    {
        size_t max_evts = 1000;
        if(!params.empty())
        {
            try
            {
                auto val = std::atoi(params.c_str());
                max_evts = val;
            }
            catch(std::exception&)
            {
                // do nothing
            }
        }
        return std::unique_ptr<my_event_source>(new my_event_source(max_evts));
    }
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_EVENT_SOURCING(my_plugin, my_event_source);
