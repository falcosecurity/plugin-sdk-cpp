// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2025 The Falco Authors.
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

#include <falcosecurity/events/codec.h>

#include <gtest/gtest.h>

#include <cstring>

// Test structures

struct SimpleStruct
{
    uint32_t a;
    uint64_t b;
    uint8_t c;
};

struct VariableLengthStruct
{
    uint32_t id;
    char data[256];
    size_t data_len;
};

struct MixedStruct
{
    uint32_t fixed1;
    char variable[128];
    size_t variable_len;
    uint64_t fixed2;
};

struct MultiVariableStruct
{
    char field1[64];
    size_t field1_len;
    uint8_t fixed;
    char field2[64];
    size_t field2_len;
};

// Tests for member_type

TEST(MemberTypeTest, Uint32Type)
{
    using MemberType = codec::member_type_t<&SimpleStruct::a>;
    EXPECT_TRUE((std::is_same_v<MemberType, uint32_t>));
}

TEST(MemberTypeTest, Uint64Type)
{
    using MemberType = codec::member_type_t<&SimpleStruct::b>;
    EXPECT_TRUE((std::is_same_v<MemberType, uint64_t>));
}

TEST(MemberTypeTest, Uint8Type)
{
    using MemberType = codec::member_type_t<&SimpleStruct::c>;
    EXPECT_TRUE((std::is_same_v<MemberType, uint8_t>));
}

TEST(MemberTypeTest, ArrayType)
{
    using MemberType = codec::member_type_t<&VariableLengthStruct::data>;
    EXPECT_TRUE((std::is_same_v<MemberType, char[256]>));
}

// Tests for class_type

TEST(ClassTypeTest, SimpleStruct)
{
    using ClassType = codec::class_type_t<&SimpleStruct::a>;
    EXPECT_TRUE((std::is_same_v<ClassType, SimpleStruct>));
}

TEST(ClassTypeTest, VariableLengthStruct)
{
    using ClassType = codec::class_type_t<&VariableLengthStruct::data>;
    EXPECT_TRUE((std::is_same_v<ClassType, VariableLengthStruct>));
}

// Tests for is_size_ptr

TEST(IsSizePtrTest, TrueForSizeT)
{
    EXPECT_TRUE((codec::is_size_ptr<&VariableLengthStruct::data_len>::value));
}

TEST(IsSizePtrTest, FalseForNonSizeT)
{
    EXPECT_FALSE((codec::is_size_ptr<&VariableLengthStruct::id>::value));
}

// Tests for Field

TEST(FieldTest, FixedField)
{
    using TestField = codec::Field<&SimpleStruct::a>;
    EXPECT_TRUE((std::is_same_v<TestField::type, uint32_t>));
    EXPECT_EQ(TestField::member_len, sizeof(uint32_t));
    EXPECT_TRUE(TestField::member_len_ptr == nullptr);
}

TEST(FieldTest, VariableField)
{
    using TestField = codec::Field<&VariableLengthStruct::data,
                                   &VariableLengthStruct::data_len>;
    EXPECT_TRUE((std::is_same_v<TestField::type, char[256]>));
    EXPECT_TRUE(TestField::member_len_ptr != nullptr);
}

// Tests for Schema

TEST(SchemaTest, NumFields)
{
    using TestSchema = codec::Schema<codec::Field<&SimpleStruct::a>,
                                     codec::Field<&SimpleStruct::b>,
                                     codec::Field<&SimpleStruct::c>>;
    EXPECT_EQ(TestSchema::num_fields, 3);
}

// Tests for Encoder - fixed fields only

TEST(EncoderTest, SimpleStruct)
{
    SimpleStruct obj{0x12345678, 0xABCDEF0123456789ULL, 0x42};

    using Schema = codec::Schema<codec::Field<&SimpleStruct::a>,
                                 codec::Field<&SimpleStruct::b>,
                                 codec::Field<&SimpleStruct::c>>;

    codec::Encoder<Schema> encoder(obj);

    uint8_t buffer[256] = {0};
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Expected size: 4 + 8 + 1 = 13 bytes
    EXPECT_EQ(encoded_size, 13);

    // Check encoded values
    uint32_t decoded_a;
    uint64_t decoded_b;
    uint8_t decoded_c;

    std::memcpy(&decoded_a, buffer, sizeof(uint32_t));
    std::memcpy(&decoded_b, buffer + 4, sizeof(uint64_t));
    std::memcpy(&decoded_c, buffer + 12, sizeof(uint8_t));

    EXPECT_EQ(decoded_a, 0x12345678);
    EXPECT_EQ(decoded_b, 0xABCDEF0123456789ULL);
    EXPECT_EQ(decoded_c, 0x42);
}

TEST(EncoderTest, InsufficientBuffer)
{
    SimpleStruct obj{0x12345678, 0xABCDEF0123456789ULL, 0x42};

    using Schema = codec::Schema<codec::Field<&SimpleStruct::a>,
                                 codec::Field<&SimpleStruct::b>,
                                 codec::Field<&SimpleStruct::c>>;

    codec::Encoder<Schema> encoder(obj);

    // Buffer too small - only 5 bytes
    // Will encode field a (4 bytes), skip field b (needs 8), encode field c (1
    // byte)
    uint8_t buffer[5] = {0};
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Should encode first and third fields: 4 + 1 = 5 bytes
    EXPECT_EQ(encoded_size, 5);

    uint32_t decoded_a;
    uint8_t decoded_c;
    std::memcpy(&decoded_a, buffer, sizeof(uint32_t));
    std::memcpy(&decoded_c, buffer + 4, sizeof(uint8_t));
    EXPECT_EQ(decoded_a, 0x12345678);
    EXPECT_EQ(decoded_c, 0x42);
}

// Tests for Encoder - variable fields

TEST(EncoderTest, VariableField)
{
    VariableLengthStruct obj;
    obj.id = 0x1234;
    const char* test_data = "Hello, World!";
    std::strcpy(obj.data, test_data);
    obj.data_len = std::strlen(test_data);

    using Schema = codec::Schema<codec::Field<&VariableLengthStruct::id>,
                                 codec::Field<&VariableLengthStruct::data,
                                              &VariableLengthStruct::data_len>>;

    codec::Encoder<Schema> encoder(obj);

    uint8_t buffer[256] = {0};
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Expected size: 4 (id) + 8 (length) + 13 (data) = 25 bytes
    EXPECT_EQ(encoded_size, 25);

    // Decode and verify
    uint32_t decoded_id;
    size_t decoded_len;
    char decoded_data[256];

    std::memcpy(&decoded_id, buffer, sizeof(uint32_t));
    std::memcpy(&decoded_len, buffer + 4, sizeof(size_t));
    std::memcpy(decoded_data, buffer + 4 + sizeof(size_t), decoded_len);
    decoded_data[decoded_len] = '\0';

    EXPECT_EQ(decoded_id, 0x1234);
    EXPECT_EQ(decoded_len, obj.data_len);
    EXPECT_STREQ(decoded_data, test_data);
}

TEST(EncoderTest, MixedFields)
{
    MixedStruct obj;
    obj.fixed1 = 0xAABBCCDD;
    const char* test_data = "Test";
    std::strcpy(obj.variable, test_data);
    obj.variable_len = std::strlen(test_data);
    obj.fixed2 = 0x1122334455667788ULL;

    using Schema = codec::Schema<
            codec::Field<&MixedStruct::fixed1>,
            codec::Field<&MixedStruct::variable, &MixedStruct::variable_len>,
            codec::Field<&MixedStruct::fixed2>>;

    codec::Encoder<Schema> encoder(obj);

    uint8_t buffer[256] = {0};
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Expected size: 4 (fixed1) + 8 (len) + 4 (data) + 8 (fixed2) = 24 bytes
    EXPECT_EQ(encoded_size, 24);

    // Verify structure
    size_t offset = 0;

    uint32_t decoded_fixed1;
    std::memcpy(&decoded_fixed1, buffer + offset, sizeof(uint32_t));
    EXPECT_EQ(decoded_fixed1, 0xAABBCCDD);
    offset += sizeof(uint32_t);

    size_t decoded_len;
    std::memcpy(&decoded_len, buffer + offset, sizeof(size_t));
    EXPECT_EQ(decoded_len, 4);
    offset += sizeof(size_t);

    char decoded_data[128];
    std::memcpy(decoded_data, buffer + offset, decoded_len);
    decoded_data[decoded_len] = '\0';
    EXPECT_STREQ(decoded_data, test_data);
    offset += decoded_len;

    uint64_t decoded_fixed2;
    std::memcpy(&decoded_fixed2, buffer + offset, sizeof(uint64_t));
    EXPECT_EQ(decoded_fixed2, 0x1122334455667788ULL);
}

TEST(EncoderTest, MultipleVariableFields)
{
    MultiVariableStruct obj;
    const char* test1 = "First";
    const char* test2 = "Second";
    std::strcpy(obj.field1, test1);
    obj.field1_len = std::strlen(test1);
    obj.fixed = 0x99;
    std::strcpy(obj.field2, test2);
    obj.field2_len = std::strlen(test2);

    using Schema =
            codec::Schema<codec::Field<&MultiVariableStruct::field1,
                                       &MultiVariableStruct::field1_len>,
                          codec::Field<&MultiVariableStruct::fixed>,
                          codec::Field<&MultiVariableStruct::field2,
                                       &MultiVariableStruct::field2_len>>;

    codec::Encoder<Schema> encoder(obj);

    uint8_t buffer[256] = {0};
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Expected size: 8 (len1) + 5 (field1) + 1 (fixed) + 8 (len2) + 6 (field2)
    // = 28 bytes
    EXPECT_EQ(encoded_size, 28);
}

// Tests for Decoder - fixed fields only

TEST(DecoderTest, SimpleStruct)
{
    // Prepare encoded data
    uint8_t buffer[256];
    size_t offset = 0;

    uint32_t val_a = 0x12345678;
    uint64_t val_b = 0xABCDEF0123456789ULL;
    uint8_t val_c = 0x42;

    std::memcpy(buffer + offset, &val_a, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    std::memcpy(buffer + offset, &val_b, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    std::memcpy(buffer + offset, &val_c, sizeof(uint8_t));
    offset += sizeof(uint8_t);

    // Decode
    SimpleStruct obj{};
    using Schema = codec::Schema<codec::Field<&SimpleStruct::a>,
                                 codec::Field<&SimpleStruct::b>,
                                 codec::Field<&SimpleStruct::c>>;

    codec::Decoder<Schema> decoder(obj);
    decoder.decode(buffer, offset);

    EXPECT_EQ(obj.a, 0x12345678);
    EXPECT_EQ(obj.b, 0xABCDEF0123456789ULL);
    EXPECT_EQ(obj.c, 0x42);
}

TEST(DecoderTest, InsufficientBuffer)
{
    // Prepare encoded data - only 5 bytes (partial)
    uint8_t buffer[5];
    uint32_t val_a = 0x12345678;
    std::memcpy(buffer, &val_a, sizeof(uint32_t));
    buffer[4] = 0xFF;

    // Decode - will decode field a (4 bytes), skip field b (needs 8), decode
    // field c (1 byte)
    SimpleStruct obj{};
    using Schema = codec::Schema<codec::Field<&SimpleStruct::a>,
                                 codec::Field<&SimpleStruct::b>,
                                 codec::Field<&SimpleStruct::c>>;

    codec::Decoder<Schema> decoder(obj);
    decoder.decode(buffer, 5);

    EXPECT_EQ(obj.a, 0x12345678);
    // b should remain uninitialized (zero) as there wasn't enough data
    EXPECT_EQ(obj.b, 0);
    // c should be decoded from buffer[4]
    EXPECT_EQ(obj.c, 0xFF);
}

// Tests for Decoder - variable fields

TEST(DecoderTest, VariableField)
{
    // Prepare encoded data
    uint8_t buffer[256];
    size_t offset = 0;

    uint32_t val_id = 0x1234;
    const char* test_data = "Hello, World!";
    size_t data_len = std::strlen(test_data);

    std::memcpy(buffer + offset, &val_id, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    std::memcpy(buffer + offset, &data_len, sizeof(size_t));
    offset += sizeof(size_t);
    std::memcpy(buffer + offset, test_data, data_len);
    offset += data_len;

    // Decode
    VariableLengthStruct obj{};
    using Schema = codec::Schema<codec::Field<&VariableLengthStruct::id>,
                                 codec::Field<&VariableLengthStruct::data,
                                              &VariableLengthStruct::data_len>>;

    codec::Decoder<Schema> decoder(obj);
    decoder.decode(buffer, offset);

    EXPECT_EQ(obj.id, 0x1234);
    EXPECT_EQ(obj.data_len, data_len);
    obj.data[obj.data_len] = '\0';
    EXPECT_STREQ(obj.data, test_data);
}

TEST(DecoderTest, MixedFields)
{
    // Prepare encoded data
    uint8_t buffer[256];
    size_t offset = 0;

    uint32_t val_fixed1 = 0xAABBCCDD;
    const char* test_data = "Test";
    size_t var_len = std::strlen(test_data);
    uint64_t val_fixed2 = 0x1122334455667788ULL;

    std::memcpy(buffer + offset, &val_fixed1, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    std::memcpy(buffer + offset, &var_len, sizeof(size_t));
    offset += sizeof(size_t);
    std::memcpy(buffer + offset, test_data, var_len);
    offset += var_len;
    std::memcpy(buffer + offset, &val_fixed2, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    // Decode
    MixedStruct obj{};
    using Schema = codec::Schema<
            codec::Field<&MixedStruct::fixed1>,
            codec::Field<&MixedStruct::variable, &MixedStruct::variable_len>,
            codec::Field<&MixedStruct::fixed2>>;

    codec::Decoder<Schema> decoder(obj);
    decoder.decode(buffer, offset);

    EXPECT_EQ(obj.fixed1, 0xAABBCCDD);
    EXPECT_EQ(obj.variable_len, var_len);
    obj.variable[obj.variable_len] = '\0';
    EXPECT_STREQ(obj.variable, test_data);
    EXPECT_EQ(obj.fixed2, 0x1122334455667788ULL);
}

TEST(DecoderTest, MultipleVariableFields)
{
    // Prepare encoded data
    uint8_t buffer[256];
    size_t offset = 0;

    const char* test1 = "First";
    size_t len1 = std::strlen(test1);
    uint8_t val_fixed = 0x99;
    const char* test2 = "Second";
    size_t len2 = std::strlen(test2);

    std::memcpy(buffer + offset, &len1, sizeof(size_t));
    offset += sizeof(size_t);
    std::memcpy(buffer + offset, test1, len1);
    offset += len1;
    std::memcpy(buffer + offset, &val_fixed, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    std::memcpy(buffer + offset, &len2, sizeof(size_t));
    offset += sizeof(size_t);
    std::memcpy(buffer + offset, test2, len2);
    offset += len2;

    // Decode
    MultiVariableStruct obj{};
    using Schema =
            codec::Schema<codec::Field<&MultiVariableStruct::field1,
                                       &MultiVariableStruct::field1_len>,
                          codec::Field<&MultiVariableStruct::fixed>,
                          codec::Field<&MultiVariableStruct::field2,
                                       &MultiVariableStruct::field2_len>>;

    codec::Decoder<Schema> decoder(obj);
    decoder.decode(buffer, offset);

    EXPECT_EQ(obj.field1_len, len1);
    obj.field1[obj.field1_len] = '\0';
    EXPECT_STREQ(obj.field1, test1);
    EXPECT_EQ(obj.fixed, 0x99);
    EXPECT_EQ(obj.field2_len, len2);
    obj.field2[obj.field2_len] = '\0';
    EXPECT_STREQ(obj.field2, test2);
}

// Round-trip tests (encode then decode)

TEST(RoundTripTest, SimpleStruct)
{
    SimpleStruct original{0xDEADBEEF, 0xCAFEBABEDEADBEEFULL, 0xFF};

    using Schema = codec::Schema<codec::Field<&SimpleStruct::a>,
                                 codec::Field<&SimpleStruct::b>,
                                 codec::Field<&SimpleStruct::c>>;

    // Encode
    codec::Encoder<Schema> encoder(original);
    uint8_t buffer[256];
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Decode
    SimpleStruct decoded{};
    codec::Decoder<Schema> decoder(decoded);
    decoder.decode(buffer, encoded_size);

    // Verify
    EXPECT_EQ(decoded.a, original.a);
    EXPECT_EQ(decoded.b, original.b);
    EXPECT_EQ(decoded.c, original.c);
}

TEST(RoundTripTest, VariableField)
{
    VariableLengthStruct original;
    original.id = 0x9876;
    const char* test_data = "Round trip test data!";
    std::strcpy(original.data, test_data);
    original.data_len = std::strlen(test_data);

    using Schema = codec::Schema<codec::Field<&VariableLengthStruct::id>,
                                 codec::Field<&VariableLengthStruct::data,
                                              &VariableLengthStruct::data_len>>;

    // Encode
    codec::Encoder<Schema> encoder(original);
    uint8_t buffer[256];
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Decode
    VariableLengthStruct decoded{};
    codec::Decoder<Schema> decoder(decoded);
    decoder.decode(buffer, encoded_size);

    // Verify
    EXPECT_EQ(decoded.id, original.id);
    EXPECT_EQ(decoded.data_len, original.data_len);
    decoded.data[decoded.data_len] = '\0';
    EXPECT_STREQ(decoded.data, original.data);
}

TEST(RoundTripTest, MixedFields)
{
    MixedStruct original;
    original.fixed1 = 0x11223344;
    const char* test_data = "Mixed fields test";
    std::strcpy(original.variable, test_data);
    original.variable_len = std::strlen(test_data);
    original.fixed2 = 0xFFEEDDCCBBAA9988ULL;

    using Schema = codec::Schema<
            codec::Field<&MixedStruct::fixed1>,
            codec::Field<&MixedStruct::variable, &MixedStruct::variable_len>,
            codec::Field<&MixedStruct::fixed2>>;

    // Encode
    codec::Encoder<Schema> encoder(original);
    uint8_t buffer[256];
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Decode
    MixedStruct decoded{};
    codec::Decoder<Schema> decoder(decoded);
    decoder.decode(buffer, encoded_size);

    // Verify
    EXPECT_EQ(decoded.fixed1, original.fixed1);
    EXPECT_EQ(decoded.variable_len, original.variable_len);
    decoded.variable[decoded.variable_len] = '\0';
    EXPECT_STREQ(decoded.variable, original.variable);
    EXPECT_EQ(decoded.fixed2, original.fixed2);
}

TEST(RoundTripTest, EmptyVariableField)
{
    VariableLengthStruct original;
    original.id = 0x5555;
    original.data[0] = '\0';
    original.data_len = 0;

    using Schema = codec::Schema<codec::Field<&VariableLengthStruct::id>,
                                 codec::Field<&VariableLengthStruct::data,
                                              &VariableLengthStruct::data_len>>;

    // Encode
    codec::Encoder<Schema> encoder(original);
    uint8_t buffer[256];
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Should be: 4 (id) + 8 (len=0) + 0 (data) = 12 bytes
    EXPECT_EQ(encoded_size, 12);

    // Decode
    VariableLengthStruct decoded{};
    codec::Decoder<Schema> decoder(decoded);
    decoder.decode(buffer, encoded_size);

    // Verify
    EXPECT_EQ(decoded.id, original.id);
    EXPECT_EQ(decoded.data_len, 0);
}

// Edge case tests

TEST(EdgeCaseTest, ZeroBuffer)
{
    SimpleStruct obj{0x12345678, 0xABCDEF0123456789ULL, 0x42};

    using Schema = codec::Schema<codec::Field<&SimpleStruct::a>,
                                 codec::Field<&SimpleStruct::b>,
                                 codec::Field<&SimpleStruct::c>>;

    codec::Encoder<Schema> encoder(obj);

    uint8_t buffer[1] = {0};
    size_t encoded_size = encoder.encode(buffer, 0);

    // Should encode nothing
    EXPECT_EQ(encoded_size, 0);
}

TEST(EdgeCaseTest, ExactBufferSize)
{
    SimpleStruct obj{0x12345678, 0xABCDEF0123456789ULL, 0x42};

    using Schema = codec::Schema<codec::Field<&SimpleStruct::a>,
                                 codec::Field<&SimpleStruct::b>,
                                 codec::Field<&SimpleStruct::c>>;

    codec::Encoder<Schema> encoder(obj);

    // Exact size buffer
    uint8_t buffer[13] = {0};
    size_t encoded_size = encoder.encode(buffer, 13);

    EXPECT_EQ(encoded_size, 13);

    // Verify all fields encoded
    SimpleStruct decoded{};
    codec::Decoder<Schema> decoder(decoded);
    decoder.decode(buffer, encoded_size);

    EXPECT_EQ(decoded.a, obj.a);
    EXPECT_EQ(decoded.b, obj.b);
    EXPECT_EQ(decoded.c, obj.c);
}

TEST(EdgeCaseTest, LargeVariableData)
{
    VariableLengthStruct obj;
    obj.id = 0xABCD;

    // Fill with large data (200 bytes)
    for(size_t i = 0; i < 200; i++)
    {
        obj.data[i] = static_cast<char>('A' + (i % 26));
    }
    obj.data[200] = '\0';
    obj.data_len = 200;

    using Schema = codec::Schema<codec::Field<&VariableLengthStruct::id>,
                                 codec::Field<&VariableLengthStruct::data,
                                              &VariableLengthStruct::data_len>>;

    // Encode
    codec::Encoder<Schema> encoder(obj);
    uint8_t buffer[512];
    size_t encoded_size = encoder.encode(buffer, sizeof(buffer));

    // Expected: 4 (id) + 8 (len) + 200 (data) = 212 bytes
    EXPECT_EQ(encoded_size, 212);

    // Decode
    VariableLengthStruct decoded{};
    codec::Decoder<Schema> decoder(decoded);
    decoder.decode(buffer, encoded_size);

    EXPECT_EQ(decoded.id, obj.id);
    EXPECT_EQ(decoded.data_len, obj.data_len);
    EXPECT_EQ(std::memcmp(decoded.data, obj.data, obj.data_len), 0);
}
