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

#pragma once

#include <falcosecurity/internal/hacks.h>
#include <falcosecurity/types.h>
#include <string>

namespace falcosecurity
{
namespace _internal
{

template<typename T>
FALCOSECURITY_INLINE void read_state_data(const ss_plugin_state_data& v, T& o);

template<typename T>
FALCOSECURITY_INLINE void write_state_data(ss_plugin_state_data& v, const T& o);

template<typename T>
FALCOSECURITY_INLINE state_value_type state_type_of(const T&);

}; // namespace _internal
}; // namespace falcosecurity

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, int8_t& o)
{
    o = v.s8;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, int16_t& o)
{
    o = v.s16;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, int32_t& o)
{
    o = v.s32;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, int64_t& o)
{
    o = v.s64;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, uint8_t& o)
{
    o = v.u8;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, uint16_t& o)
{
    o = v.u16;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, uint32_t& o)
{
    o = v.u32;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, uint64_t& o)
{
    o = v.u64;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, bool& o)
{
    o = v.b != 0;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::read_state_data(
        const falcosecurity::_internal::ss_plugin_state_data& v, std::string& o)
{
    o.assign(v.str);
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const int8_t& o)
{
    v.s8 = o;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const int16_t& o)
{
    v.s16 = o;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const int32_t& o)
{
    v.s32 = o;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const int64_t& o)
{
    v.s64 = o;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const uint8_t& o)
{
    v.u8 = o;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const uint16_t& o)
{
    v.u16 = o;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const uint32_t& o)
{
    v.u32 = o;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const uint64_t& o)
{
    v.u64 = o;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const bool& o)
{
    v.b = o;
}

template<>
FALCOSECURITY_INLINE void falcosecurity::_internal::write_state_data(
        falcosecurity::_internal::ss_plugin_state_data& v, const std::string& o)
{
    v.str = o.c_str();
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const int8_t&)
{
    return state_value_type::SS_PLUGIN_ST_INT8;
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const int16_t&)
{
    return state_value_type::SS_PLUGIN_ST_INT16;
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const int32_t&)
{
    return state_value_type::SS_PLUGIN_ST_INT32;
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const int64_t&)
{
    return state_value_type::SS_PLUGIN_ST_INT64;
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const uint8_t&)
{
    return state_value_type::SS_PLUGIN_ST_UINT8;
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const uint16_t&)
{
    return state_value_type::SS_PLUGIN_ST_UINT16;
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const uint32_t&)
{
    return state_value_type::SS_PLUGIN_ST_UINT32;
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const uint64_t&)
{
    return state_value_type::SS_PLUGIN_ST_UINT64;
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const bool&)
{
    return state_value_type::SS_PLUGIN_ST_BOOL;
}

template<>
FALCOSECURITY_INLINE falcosecurity::state_value_type
falcosecurity::_internal::state_type_of(const std::string&)
{
    return state_value_type::SS_PLUGIN_ST_STRING;
}
