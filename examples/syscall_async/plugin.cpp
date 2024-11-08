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

class my_plugin
{
    public:
    virtual ~my_plugin() = default;

    std::string get_name() { return "syscall-async-example"; }

    std::string get_version() { return "0.1.0"; }

    std::string get_description() { return "some description"; }

    std::string get_contact() { return "some contact"; }

    // (optional)
    bool set_config(falcosecurity::set_config_input& i)
    {
        logger.log("new config!");
        return true;
    }

    // (optional)
    void destroy() {}

    bool init(falcosecurity::init_input& i)
    {
        logger = i.get_logger();
        logger.log("plugin initialized");

        m_async_sleep_ms = 1000;
        if(!i.get_config().empty())
        {
            try
            {
                auto val = std::atoi(i.get_config().c_str());
                m_async_sleep_ms = val;
            }
            catch(std::exception&)
            {
                // do nothing
            }
        }
        return true;
    }

    std::vector<std::string> get_async_events()
    {
        return {"samplenotification"};
    }

    // (optional)
    std::vector<std::string> get_async_event_sources() { return {"syscall"}; }

    bool start_async_events(
            std::shared_ptr<falcosecurity::async_event_handler_factory> f)
    {
        m_async_thread_quit = false;
        m_async_thread = std::thread(&my_plugin::async_thread_loop, this,
                                     std::move(f->new_handler()));
        return true;
    }

    bool stop_async_events() noexcept
    {
        m_async_thread_quit = true;
        if(m_async_thread.joinable())
        {
            m_async_thread.join();
        }
        return true;
    }

    void async_thread_loop(
            std::unique_ptr<falcosecurity::async_event_handler> h) noexcept
    {
        std::string msg;
        uint64_t count = 0;
        falcosecurity::events::asyncevent_e_encoder enc;

        // note: the code below can throw exceptions and they should be catched
        while(!m_async_thread_quit)
        {
            msg = "notification #" + std::to_string(count++);
            enc.set_tid(1);
            enc.set_name("samplenotification");
            enc.set_data((void*)msg.c_str(), msg.size() + 1);
            enc.encode(h->writer());
            h->push();
            std::this_thread::sleep_for(
                    std::chrono::milliseconds(m_async_sleep_ms));
        }
    }

    // (optional)
    void dump_state(std::unique_ptr<falcosecurity::async_event_handler> h)
    {
        falcosecurity::events::asyncevent_e_encoder enc;
        std::string msg;
        for(int i = 0; i < 10; i++)
        {
            msg = "dumped event #" + std::to_string(i);
            enc.set_tid(1);
            enc.set_name("samplenotification");
            enc.set_data((void*)msg.c_str(), msg.size() + 1);
            enc.encode(h->writer());
            h->push();
        }
    }

    private:
    int m_async_sleep_ms;
    std::thread m_async_thread;
    std::atomic<bool> m_async_thread_quit;
    falcosecurity::logger logger;
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
