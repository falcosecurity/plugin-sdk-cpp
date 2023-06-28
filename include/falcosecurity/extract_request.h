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
#include <stdexcept>
#include <string>
#include <vector>

namespace falcosecurity
{

class extract_request
{
    public:
    FALCOSECURITY_INLINE
    extract_request(_internal::ss_plugin_extract_field* r = nullptr):
            m_req(r), m_result(), m_result_strings(), m_result_bufs()
    {
    }
    FALCOSECURITY_INLINE
    extract_request(extract_request&&) = default;
    FALCOSECURITY_INLINE
    extract_request& operator=(extract_request&&) = default;
    FALCOSECURITY_INLINE
    extract_request(const extract_request&) = default;
    FALCOSECURITY_INLINE
    extract_request& operator=(const extract_request&) = default;

    FALCOSECURITY_INLINE
    void set_request(_internal::ss_plugin_extract_field* r)
    {
        if(!r)
        {
            throw std::invalid_argument(
                    "invalid null pointer passed to extract request");
        }
        m_req = r;
    }

    FALCOSECURITY_INLINE
    uint64_t get_field_id() const { return m_req->field_id; }

    FALCOSECURITY_INLINE
    const char* get_field() const { return m_req->field; }

    FALCOSECURITY_INLINE
    field_value_type get_field_type() const
    {
        return static_cast<field_value_type>(m_req->ftype);
    }

    FALCOSECURITY_INLINE
    const char* get_arg_key() const { return m_req->arg_key; }

    FALCOSECURITY_INLINE
    uint64_t get_arg_index() const { return m_req->arg_index; }

    FALCOSECURITY_INLINE
    bool is_arg_present() const { return m_req->arg_present != 0; }

    FALCOSECURITY_INLINE
    bool is_list() const { return m_req->flist != 0; }

    template<typename Iter>
    FALCOSECURITY_INLINE void set_value(Iter begin, Iter end, bool copy = true)
    {
        check_list(true);
        size_t i = 0;
        while(begin != end)
        {
            set_value(*begin, i, copy);
            ++begin;
            ++i;
        }
    }

    FALCOSECURITY_INLINE
    void set_value(bool v, bool copy = true)
    {
        check_list(false);
        check_type(get_field_type() == field_value_type::FTYPE_BOOL);
        set_value(v, 0, copy);
    }

    FALCOSECURITY_INLINE
    void set_value(uint64_t v, bool copy = true)
    {
        check_list(false);
        check_type(get_field_type() == field_value_type::FTYPE_UINT64 ||
                   get_field_type() == field_value_type::FTYPE_RELTIME ||
                   get_field_type() == field_value_type::FTYPE_ABSTIME);
        set_value(v, 0, copy);
    }

    FALCOSECURITY_INLINE
    void set_value(const char* v, bool copy = true)
    {
        check_list(false);
        check_type(get_field_type() == field_value_type::FTYPE_STRING);
        set_value(v, 0, copy);
    }

    FALCOSECURITY_INLINE
    void set_value(const std::string& v, bool copy = true)
    {
        check_list(false);
        check_type(get_field_type() == field_value_type::FTYPE_STRING);
        set_value(v, 0, copy);
    }

    FALCOSECURITY_INLINE
    void set_value(void* buf, uint32_t bufsize, bool copy = true)
    {
        check_list(false);
        check_type(get_field_type() == field_value_type::FTYPE_IPNET ||
                   get_field_type() == field_value_type::FTYPE_IPADDR);
        set_value(buf, bufsize, 0, copy);
    }

    private:
    union result
    {
        const char* str;
        uint64_t u64;
        uint32_t u32;
        _internal::ss_plugin_bool boolean;
        _internal::ss_plugin_byte_buffer buf;
    };

    _internal::ss_plugin_extract_field* m_req;
    std::vector<result> m_result;
    std::vector<std::string> m_result_strings;
    std::vector<std::vector<uint8_t>> m_result_bufs;

    FALCOSECURITY_INLINE
    void check_list(bool l) const
    {
        FALCOSECURITY_ASSERT(
                l == is_list(),
                std::string(l ? "expected" : "unexpected") +
                        " list value type passed to extract request");
    }

    FALCOSECURITY_INLINE
    void check_type(bool check) const
    {
        FALCOSECURITY_ASSERT(
                check, "invalid value set in extract request: expected type " +
                               falcosecurity::to_string(get_field_type()));
    }

    FALCOSECURITY_INLINE void resize_result(size_t s)
    {
        if(m_result.size() <= s)
        {
            m_result.resize(s + 1);
            m_result_strings.resize(s + 1);
            m_result_bufs.resize(s + 1);
        }
    }

    FALCOSECURITY_INLINE
    void set_value(bool v, size_t pos, bool copy)
    {
        resize_result(pos);
        auto r = reinterpret_cast<_internal::ss_plugin_bool*>(m_result.data());
        r[pos] = (_internal::ss_plugin_bool)(v ? 1 : 0);
        m_req->res.boolean = &r[pos];
        m_req->res_len = pos + 1;
    }

    FALCOSECURITY_INLINE
    void set_value(uint64_t v, size_t pos, bool copy)
    {
        resize_result(pos);
        auto r = reinterpret_cast<uint64_t*>(m_result.data());
        r[pos] = v;
        m_req->res.u64 = &r[pos];
        m_req->res_len = pos + 1;
    }

    FALCOSECURITY_INLINE
    void set_value(const char* v, size_t pos, bool copy)
    {
        resize_result(pos);
        auto r = reinterpret_cast<const char**>(m_result.data());
        if(copy)
        {
            m_result_strings[pos].assign(v);
            r[pos] = m_result_strings[pos].c_str();
        }
        else
        {
            r[pos] = v;
        }
        m_req->res.str = &r[pos];
        m_req->res_len = pos + 1;
    }

    FALCOSECURITY_INLINE
    void set_value(void* buf, uint32_t bufsize, size_t pos, bool copy)
    {
        resize_result(pos);
        auto r = reinterpret_cast<_internal::ss_plugin_byte_buffer*>(
                m_result.data());
        if(copy)
        {
            if(m_result_bufs[pos].size() < bufsize)
            {
                m_result_bufs[pos].resize(bufsize);
            }
            memcpy(m_result_bufs[pos].data(), buf, bufsize);
            r[pos].ptr = m_result_bufs[pos].data();
            r[pos].len = (uint32_t)bufsize;
        }
        else
        {
            r[pos].ptr = buf;
            r[pos].len = (uint32_t)bufsize;
        }
        m_req->res.buf = &r[pos];
        m_req->res_len = pos + 1;
    }

    FALCOSECURITY_INLINE
    void set_value(const std::string& v, size_t pos, bool copy)
    {
        set_value(v.c_str(), pos, copy);
    }
};

}; // namespace falcosecurity
