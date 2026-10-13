// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 The Falco Authors.
//
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <falcosecurity/table.h>

#include <gtest/gtest.h>

using namespace falcosecurity;

namespace
{
int g_entry;
int g_released;

_internal::ss_plugin_table_entry_t*
fake_get(_internal::ss_plugin_table_t*, const _internal::ss_plugin_state_data*)
{
    return &g_entry;
}

void fake_release(_internal::ss_plugin_table_t*,
                  _internal::ss_plugin_table_entry_t*)
{
    g_released++;
}

_internal::ss_plugin_bool
fake_iterate(_internal::ss_plugin_table_t*,
             _internal::ss_plugin_table_iterator_func_t it,
             _internal::ss_plugin_table_iterator_state_t* s)
{
    it(s, &g_entry);
    it(s, &g_entry);
    return 1;
}

class table_test : public ::testing::Test
{
    protected:
    void SetUp() override
    {
        g_released = 0;
        m_vtable = {};
        m_vtable.get_table_entry = fake_get;
        m_vtable.release_table_entry = fake_release;
        m_vtable.iterate_entries = fake_iterate;
    }

    _internal::ss_plugin_table_reader_vtable_ext m_vtable;
    int m_table_handle = 0;
};
} // namespace

TEST_F(table_test, iteration_does_not_release_borrowed_entries)
{
    table_reader reader(&m_vtable, nullptr, nullptr);
    table t("t", _internal::SS_PLUGIN_ST_INT64, &m_table_handle);

    int visited = 0;
    t.iterate_entries(reader,
                      [&](const table_entry&)
                      {
                          visited++;
                          return true;
                      });

    EXPECT_EQ(visited, 2);
    EXPECT_EQ(g_released, 0);
}

TEST_F(table_test, entry_from_get_is_released_once)
{
    table_reader reader(&m_vtable, nullptr, nullptr);
    table t("t", _internal::SS_PLUGIN_ST_INT64, &m_table_handle);

    {
        auto e = t.get_entry(reader, int64_t(1));
        auto moved = std::move(e);
        EXPECT_EQ(g_released, 0);
    }

    EXPECT_EQ(g_released, 1);
}
