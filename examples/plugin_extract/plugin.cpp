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

    std::string get_name() { return "plugin-extract-example"; }

    std::string get_version() { return "0.1.0"; }

    std::string get_description() { return "some description"; }

    std::string get_contact() { return "some contact"; }

    // (optional)
    std::vector<std::string> get_extract_event_sources() { return {"example"}; }

    std::vector<falcosecurity::field_info> get_fields()
    {
        using ft = falcosecurity::field_value_type;
        return {
                {ft::FTYPE_STRING, "example.msg", "Example Message",
                 "Message written inside example events"},
        };
    }

    // (optional)
    bool set_config(falcosecurity::set_config_input& i)
    {
        logger.log("new config!");
        return true;
    }

    // (optional)
    void destroy() { logger.log("plugin destroyed"); }

    bool init(falcosecurity::init_input& i)
    {
        logger = i.get_logger();
        logger.log("plugin initialized");

        return true;
    }

    bool extract(const falcosecurity::extract_fields_input& in)
    {
        auto& req = in.get_extract_request();
        switch(req.get_field_id())
        {
        case 0: // example.msg
        {
            auto& evt = in.get_event_reader();
            falcosecurity::events::pluginevent_e_decoder dec(evt);

            uint32_t msglen = 0;
            auto msg = (const char*)dec.get_data(msglen);

            // note: we can avoid an extra mem copy because the string
            // is owned by the event itself
            req.set_value(msg, false);
            return true;
        }
        default:
            break;
        }

        return false;
    }

    private:
    falcosecurity::logger logger;
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(my_plugin);
