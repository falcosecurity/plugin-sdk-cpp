#pragma once

#include <cstring>
#include <iomanip>
#include <iostream>
#include <utility>

#include <stdint.h>

namespace codec
{

// Helpers to get member type and class.
template<auto MemberPtr> struct member_type;

template<typename ClassT, typename MemberT, MemberT ClassT::*MemberPtr>
struct member_type<MemberPtr>
{
    using type = MemberT;
};

template<auto MemberT>
using member_type_t = typename member_type<MemberT>::type;

template<auto MemberPtr> struct class_type;

template<typename ClassT, typename MemberT, MemberT ClassT::*MemberPtr>
struct class_type<MemberPtr>
{
    using type = ClassT;
};

template<auto MemberPtr>
using class_type_t = typename class_type<MemberPtr>::type;

template<auto Ptr> struct is_size_ptr : std::false_type
{
};

template<typename ClassT, size_t ClassT::*Ptr>
struct is_size_ptr<Ptr> : std::true_type
{
};

// Schema

template<auto MemberPtr, auto MemberLenPtr = nullptr> struct Field
{

    using type = member_type_t<MemberPtr>;
    static constexpr auto member_ptr = MemberPtr;
    static constexpr auto member_len_ptr = MemberLenPtr;
    static constexpr size_t member_len = sizeof(type);

    static_assert(MemberLenPtr == nullptr || is_size_ptr<MemberLenPtr>::value,
                  "Length member must be size_t");

    static_assert(MemberLenPtr == nullptr || std::is_array_v<type> ||
                          std::is_pointer_v<type>,
                  "A variable type must be an array or a pointer");
};

template<typename... Fields> struct Schema
{
    static constexpr size_t num_fields = sizeof...(Fields);
    using fields = std::tuple<Fields...>;
};

// Encoder

template<typename SchemaT> class Encoder
{
    public:
    using StructT = class_type_t<
            std::tuple_element_t<0, typename SchemaT::fields>::member_ptr>;
    explicit Encoder(const StructT& obj): m_obj(obj) {}

    size_t encode(uint8_t* buf, size_t buf_size)
    {
        uint8_t* curr_ptr = buf;
        size_t available = buf_size;
        encode_fields(curr_ptr, available);
        return buf_size - available;
    }

    private:
    template<typename Field>
    void encode_fixed_field(uint8_t*& buf, size_t& available)
    {
        using FieldType = typename Field::type;
        static_assert(std::is_trivially_copyable_v<FieldType>,
                      "Fixed fields must be trivially copyable");

        if(available >= Field::member_len)
        {
            const FieldType& src = m_obj.*(Field::member_ptr);
            std::memcpy(buf, &src, Field::member_len);
            buf += Field::member_len;
            available -= Field::member_len;
        }
    }

    template<typename Field>
    void encode_variable_field(uint8_t*& buf, size_t& available)
    {
        using FieldMemberPtrClass = class_type_t<Field::member_ptr>;
        using FieldMemberLenPtrClass = class_type_t<Field::member_len_ptr>;
        static_assert(
                std::is_same_v<FieldMemberPtrClass, FieldMemberLenPtrClass>,
                "The len of a variable field must belong to the same struct of "
                "the variable field.");

        using FieldType = typename Field::type;
        const size_t& len = m_obj.*(Field::member_len_ptr);

        if(available >= sizeof(size_t) + len)
        {
            // First we write the len
            std::memcpy(buf, &len, sizeof(size_t));
            buf += sizeof(size_t);
            available -= sizeof(size_t);

            // then we write the actual content
            const FieldType& src = m_obj.*(Field::member_ptr);
            std::memcpy(buf, &src, len);
            buf += len;
            available -= len;
        }
    }

    template<size_t Is> void encode_field(uint8_t*& buf, size_t& available)
    {
        using Field = std::tuple_element_t<Is, typename SchemaT::fields>;
        if constexpr(Field::member_len_ptr == nullptr)
        {
            encode_fixed_field<Field>(buf, available);
        }
        else
        {
            encode_variable_field<Field>(buf, available);
        }
    }

    template<size_t... Is>
    void encode_fields_impl(uint8_t*& buf, size_t& available,
                            std::index_sequence<Is...>)
    {
        (encode_field<Is>(buf, available), ...);
    }

    void encode_fields(uint8_t*& buf, size_t& available)
    {
        encode_fields_impl(buf, available,
                           std::make_index_sequence<SchemaT::num_fields>{});
    }

    // Compile time checks

    using SchemaFields = typename SchemaT::fields;
    template<size_t I>
    using FieldClassT =
            class_type_t<std::tuple_element_t<I, SchemaFields>::member_ptr>;

    template<size_t... Is>
    static constexpr bool check_same_struct(std::index_sequence<Is...>)
    {
        return (std::is_same_v<StructT, FieldClassT<Is>> && ...);
    }

    static_assert(
            check_same_struct(std::make_index_sequence<SchemaT::num_fields>{}),
            "All fields must belong to the same struct");

    static_assert(SchemaT::num_fields > 0,
                  "The schema must define at least a field.");

    const StructT& m_obj;
};

template<typename SchemaT> class Decoder
{
    public:
    using StructT = class_type_t<
            std::tuple_element_t<0, typename SchemaT::fields>::member_ptr>;
    explicit Decoder(StructT& obj): m_obj(obj) {}

    void decode(uint8_t* buf, const size_t& available)
    {
        uint8_t* cur_ptr = buf;
        size_t left = available;

        decode_fields(cur_ptr, left);
    }

    private:
    template<typename Field>
    void decode_fixed_field(uint8_t*& buf, size_t& left)
    {
        using FieldType = typename Field::type;
        static_assert(std::is_trivially_copyable_v<FieldType>,
                      "Fixed fields must be trivially copyable");

        if(left >= Field::member_len)
        {
            FieldType& dst = m_obj.*(Field::member_ptr);
            std::memcpy(&dst, buf, Field::member_len);
            buf += Field::member_len;
            left -= Field::member_len;
        }
    }

    template<typename Field>
    void decode_variable_field(uint8_t*& buf, size_t& left)
    {
        using FieldMemberPtrClass = class_type_t<Field::member_ptr>;
        using FieldMemberLenPtrClass = class_type_t<Field::member_len_ptr>;
        static_assert(
                std::is_same_v<FieldMemberPtrClass, FieldMemberLenPtrClass>,
                "The len of a variable field must belong to the same struct of "
                "the variable field.");

        size_t& len = m_obj.*(Field::member_len_ptr);

        if(left >= sizeof(size_t))
        {
            std::memcpy(&len, buf, sizeof(size_t));
            buf += sizeof(size_t);
            left -= sizeof(size_t);

            if(left >= len)
            {

                using FieldType = typename Field::type;
                FieldType& dst = m_obj.*(Field::member_ptr);
                std::memcpy(&dst, buf, len);
                buf += len;
                left -= len;
            }
        }
    }

    template<size_t Is> void decode_field(uint8_t*& buf, size_t& left)
    {
        using Field = std::tuple_element_t<Is, typename SchemaT::fields>;
        if constexpr(Field::member_len_ptr == nullptr)
        {
            decode_fixed_field<Field>(buf, left);
        }
        else
        {
            decode_variable_field<Field>(buf, left);
        }
    }

    // Compile time checks

    template<size_t... Is>
    void decode_fields_impl(uint8_t*& buf, size_t& left,
                            std::index_sequence<Is...>)
    {
        (decode_field<Is>(buf, left), ...);
    }

    void decode_fields(uint8_t*& buf, size_t& left)
    {
        decode_fields_impl(buf, left,
                           std::make_index_sequence<SchemaT::num_fields>{});
    }

    using SchemaFields = typename SchemaT::fields;
    template<size_t I>
    using FieldClassT =
            class_type_t<std::tuple_element_t<I, SchemaFields>::member_ptr>;

    template<size_t... Is>
    static constexpr bool check_same_struct(std::index_sequence<Is...>)
    {
        return (std::is_same_v<StructT, FieldClassT<Is>> && ...);
    }

    static_assert(
            check_same_struct(std::make_index_sequence<SchemaT::num_fields>{}),
            "All fields must belong to the same struct");

    static_assert(SchemaT::num_fields > 0,
                  "The schema must define at least a field.");

    StructT& m_obj;
};

} // namespace codec
