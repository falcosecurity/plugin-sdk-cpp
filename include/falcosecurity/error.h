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

#pragma once

#include <falcosecurity/internal/hacks.h>
#include <falcosecurity/internal/deps.h>
#include <memory>
#include <string>

namespace falcosecurity
{

namespace _internal
{

template<typename T> class err_msg_container
{
    public:
    FALCOSECURITY_INLINE err_msg_container(T&& m): m_val(new T(std::move(m))) {}

    FALCOSECURITY_INLINE err_msg_container(const T& m): m_val(new T(m)) {}

    FALCOSECURITY_INLINE
    err_msg_container() = default;

    FALCOSECURITY_INLINE
    ~err_msg_container() = default;

    FALCOSECURITY_INLINE
    err_msg_container(err_msg_container&& o) { m_val = std::move(o.m_val); };

    FALCOSECURITY_INLINE
    err_msg_container& operator=(err_msg_container&& o)
    {
        m_val = std::move(o.m_val);
        return *this;
    }

    FALCOSECURITY_INLINE
    err_msg_container(const err_msg_container& o)
    {
        if(o.m_val != nullptr)
        {
            m_val.reset(new T(*o.m_val.get()));
            return;
        }
        m_val.reset(nullptr);
    };

    FALCOSECURITY_INLINE
    err_msg_container& operator=(const err_msg_container& o)
    {
        if(o.m_val != nullptr)
        {
            m_val.reset(new T(*o.m_val.get()));
            return *this;
        }
        m_val.reset(nullptr);
        return *this;
    };

    FALCOSECURITY_INLINE
    bool operator==(const err_msg_container& o)
    {
        if(m_val != nullptr && o.m_val != nullptr)
        {
            return *m_val.get() == *o.m_val.get();
        }
        return m_val == o.m_val;
    }

    FALCOSECURITY_INLINE
    bool operator!=(const err_msg_container& o) { return !(*this == o); }

    FALCOSECURITY_INLINE
    const T& value() const
    {
        throw_if_null();
        return *m_val.get();
    }

    FALCOSECURITY_INLINE
    T&& value()
    {
        throw_if_null();
        return std::move(*m_val.get());
    }

    private:
    FALCOSECURITY_INLINE
    void throw_if_null() const
    {
        if(m_val == nullptr)
        {
            FALCOSECURITY_THROW(std::runtime_error("error value is null"));
        }
    }

    // note: storing a pointer instead of an actual value guarantees that
    // the error message size is object-independent and as small as possible
    // (e.g. sizeof(err_msg_container) == sizeof(uintptr_t))
    std::unique_ptr<T> m_val;
};

}; // namespace _internal

using err_msg = _internal::err_msg_container<std::string>;

using err = tl::unexpected<err_msg>;

template<typename T> using res = tl::expected<T, err_msg>;

}; // namespace falcosecurity

static_assert(sizeof(falcosecurity::err_msg) == sizeof(uintptr_t));
