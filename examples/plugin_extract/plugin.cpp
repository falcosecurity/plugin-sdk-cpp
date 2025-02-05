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
#include <iostream>

class my_table : public falcosecurity::base_table<my_table>
{
    public:
    my_table() : falcosecurity::base_table<my_table>() {};

    std::string get_name()
    {
        return "my_table";
    }

    falcosecurity::state_value_type get_key_type()
    {
        return falcosecurity::state_value_type::SS_PLUGIN_ST_INT64;
    }

    std::vector<falcosecurity::table_field_info> list_fields()
    {
        std::vector<falcosecurity::table_field_info> infos;
        auto fi = falcosecurity::table_field_info(falcosecurity::_internal::SS_PLUGIN_ST_INT8, "my_field", false);
        infos.push_back(fi);

        return infos;
    }
};

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

        auto& t = i.tables();

        // add the custom table
        m_table = std::make_unique<my_table>();
        t.add_table(m_table->get_table_input());

        // get the table fields through the api to check if the conversion works
        m_falco_table = t.get_table("my_table", falcosecurity::state_value_type::SS_PLUGIN_ST_INT64);

        auto fields = m_falco_table.list_fields(t.fields());

        for(auto& f : fields)
        {
            std::cout << "Field name: " << f.name << std::endl;
        }


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

    // table handle through api
    falcosecurity::table m_falco_table;
    // my actual table
    std::unique_ptr<my_table> m_table;
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(my_plugin);
