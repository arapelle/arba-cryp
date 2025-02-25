#include <arba/cryp/config.hpp>
#include <arba/cryp/symcrypt.hpp>

#include <arba/hash/murmur_hash.hpp>
#include <arba/rand/urng.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <ranges>

auto long_data()
{
    return std::vector<uint8_t>{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0,    1,    2,    3,    4,    5,    6,    7,    8,    9 };
}

auto short_data()
{
    return std::vector<uint8_t>{ 0, 1 };
}

auto empty_data()
{
    return std::vector<uint8_t>{};
}

auto zero_data()
{
    return std::vector<uint8_t>{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
}

auto seq_data()
{
    return std::vector<uint8_t>{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
}

template <std::ranges::input_range range_type>
void display_data(const range_type& data)
{
    std::cout << "{ ";
    for (const auto& value : data)
        printf("0x%02x, ", value);
    std::cout << "}" << std::endl;
}

//-----

TEST(symcrypt_tests, test_construct_key)
{
    arba::cryp::symcrypt::crypto_key key{ 16, 216, 58, 6, 182, 126, 102, 212, 190, 60, 177, 6, 172, 106, 62, 46 };
    cryp::symcrypt::crypto_key expected_key = key;
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), expected_key);
}

TEST(symcrypt_tests, test_construct_uuid)
{
    uuid::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), key.data());
}

TEST(symcrypt_tests, test_construct_string_view)
{
    std::string_view key("my password 01A%^o");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), hash::neutral_murmur_hash_array_16(key.data(), key.length()));
}

TEST(symcrypt_tests, test_set_key_key)
{
    cryp::symcrypt::crypto_key key{ 16, 216, 58, 6, 182, 126, 102, 212, 190, 60, 177, 6, 172, 106, 62, 46 };
    cryp::symcrypt symcrypt(key);
    cryp::symcrypt::crypto_key new_key{ 254, 241, 196, 48, 101, 5, 236, 98, 32, 182, 176, 74, 60, 188, 4, 102 };
    ASSERT_NE(symcrypt.key(), new_key);
    symcrypt.set_key(new_key);
    ASSERT_EQ(symcrypt.key(), new_key);
}

TEST(symcrypt_tests, test_set_key_uuid)
{
    uuid::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), key.data());
    uuid::uuid new_key("8defc670-716b-4242-9932-3009bf3e6ecc");
    ASSERT_NE(symcrypt.key(), new_key.data());
    symcrypt.set_key(new_key);
    ASSERT_EQ(symcrypt.key(), new_key.data());
}

TEST(symcrypt_tests, test_set_key_string_view)
{
    std::string_view key("my password 01A%^o");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), hash::neutral_murmur_hash_array_16(key.data(), key.length()));
    std::string_view new_key("8defc670-716b-4242-9932-3009bf3e6ecc");
    ASSERT_NE(symcrypt.key(), hash::neutral_murmur_hash_array_16(new_key.data(), new_key.length()));
    symcrypt.set_key(new_key);
    ASSERT_EQ(symcrypt.key(), hash::neutral_murmur_hash_array_16(new_key.data(), new_key.length()));
}

TEST(symcrypt_tests, test_long_data)
{
    uuid::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key, rand::urng_u8<0, 255>(42));
    // Init clear data
    std::vector<uint8_t> init_data = long_data();
    std::vector<uint8_t> data = init_data;
    ASSERT_EQ(data, init_data);
    // First encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> first_expected_encryped_data{
        0x9b, 0x08, 0x64, 0xa6, 0x3b, 0x9f, 0x87, 0x3b, 0x3d, 0x86, 0x2f, 0x3d, 0xe5, 0x83, 0x7c,
        0x22, 0xab, 0x46, 0x25, 0x18, 0x71, 0x71, 0x1a, 0x79, 0x52, 0x7a, 0x8e, 0x00, 0xab,
    };
    ASSERT_EQ(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    // First decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
    // Second encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> second_expected_encryped_data{
        0xc1, 0x64, 0x0c, 0x23, 0x39, 0x2d, 0x36, 0xcf, 0xfb, 0x4a, 0xf5, 0xf4, 0xa4, 0x19, 0x11,
        0x63, 0xb9, 0xb5, 0x93, 0x98, 0x5c, 0x39, 0xc1, 0xad, 0x3d, 0xcd, 0x3c, 0x44, 0x68,
    };
    ASSERT_EQ(data, second_expected_encryped_data);
    ASSERT_NE(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    // Second decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_short_data)
{
    uuid::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key, rand::urng_u8<0, 255>(42));
    // Init clear data
    std::vector<uint8_t> init_data = short_data();
    std::vector<uint8_t> data = init_data;
    ASSERT_LT(data.size(), cryp::symcrypt::min_data_size);
    ASSERT_EQ(data, init_data);
    // First encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> first_expected_encryped_data{
        0x4e, 0xc1, 0x70, 0x4b, 0x6a, 0x3b, 0xa8, 0xab, 0x64, 0xdd, 0xc3, 0xec, 0x49,
        0x44, 0x5f, 0x5f, 0xfe, 0xef, 0xa4, 0x1f, 0x48, 0x74, 0x6d, 0x6c, 0x21,
    };
    ASSERT_EQ(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    ASSERT_GT(data.size(), cryp::symcrypt::min_data_size);
    // First decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
    // Second encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> second_expected_encryped_data{
        0x1c, 0x8e, 0x2b, 0x19, 0xfc, 0x50, 0x70, 0x9d, 0xd1, 0xb5, 0xd4, 0xaa, 0x00,
        0x92, 0x2a, 0xc8, 0xdd, 0x80, 0x54, 0xd0, 0xaa, 0x5b, 0x2d, 0x8a, 0x1e,
    };
    ASSERT_EQ(data, second_expected_encryped_data);
    ASSERT_NE(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    // Second decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_empty_data)
{
    uuid::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key, rand::urng_u8<0, 255>(42));
    // Init clear data
    std::vector<uint8_t> init_data = empty_data();
    std::vector<uint8_t> data = init_data;
    ASSERT_EQ(data, init_data);
    // First encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> first_expected_encryped_data{
        0x8a, 0xd2, 0xa5, 0x3d, 0x08, 0xc1, 0x45, 0xf3, 0xaf, 0x7f, 0x8f, 0x44, 0xc2,
        0x88, 0x50, 0xf1, 0x61, 0xab, 0x73, 0x3b, 0xca, 0xc4, 0xd5, 0x5f, 0xcb,
    };
    ASSERT_EQ(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    // First decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
    // Second encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> second_expected_encryped_data{
        0x3b, 0xed, 0x04, 0x51, 0xda, 0x0a, 0x84, 0x0d, 0xfc, 0x2a, 0x5a, 0xdc, 0xeb,
        0x17, 0x6c, 0x76, 0x2a, 0xae, 0xb5, 0xa9, 0x2f, 0x09, 0xc0, 0xc4, 0x4e,
    };
    ASSERT_EQ(data, second_expected_encryped_data);
    ASSERT_NE(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    // Second decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_zero_data)
{
    uuid::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key, rand::urng_u8<0, 255>(42));
    // Init clear data
    std::vector<uint8_t> init_data = zero_data();
    std::vector<uint8_t> data = init_data;
    ASSERT_EQ(data, init_data);
    // First encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> first_expected_encryped_data{
        0xf6, 0x30, 0x47, 0xd6, 0xde, 0xaf, 0xf2, 0xde, 0x05, 0x69, 0x2f, 0xd2, 0x5c, 0x35, 0xde,
        0x07, 0xa2, 0x21, 0x15, 0x0f, 0x06, 0x3e, 0x71, 0x1a, 0x79, 0x52, 0x7a, 0x8e, 0x00, 0xab,
    };
    ASSERT_EQ(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    // First decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
    // Second encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> second_expected_encryped_data{
        0x1d, 0x47, 0x08, 0x33, 0x29, 0x2e, 0xc8, 0x80, 0xfd, 0x4c, 0xf5, 0xf2, 0x09, 0x40, 0x80,
        0x62, 0x95, 0xfc, 0x62, 0x86, 0x4b, 0x63, 0x39, 0xc1, 0xad, 0x3d, 0xcd, 0x3c, 0x44, 0x68,
    };
    ASSERT_EQ(data, second_expected_encryped_data);
    ASSERT_NE(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    // Second decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_seq_data)
{
    uuid::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key, rand::urng_u8<0, 255>(42));
    // Init clear data
    std::vector<uint8_t> init_data = seq_data();
    std::vector<uint8_t> data = init_data;
    ASSERT_EQ(data, init_data);
    // First encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> first_expected_encryped_data{
        0xf6, 0x10, 0x94, 0xdc, 0x7c, 0xff, 0xfb, 0x3d, 0x16, 0x72, 0xd0, 0xdd, 0x86, 0x42,
        0xef, 0x25, 0xc2, 0xc8, 0xc9, 0x02, 0x71, 0x1a, 0x79, 0x52, 0x7a, 0x8e, 0x00, 0xab,
    };
    ASSERT_EQ(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    // First decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
    // Second encrypt
    symcrypt.encrypt(data);
    std::vector<uint8_t> second_expected_encryped_data{
        0x1d, 0x48, 0x18, 0x36, 0x31, 0x33, 0xa6, 0x74, 0x81, 0x97, 0x69, 0x12, 0x9c, 0xd2,
        0xe4, 0x02, 0xa5, 0x83, 0x86, 0xa8, 0x39, 0xc1, 0xad, 0x3d, 0xcd, 0x3c, 0x44, 0x68,
    };
    ASSERT_EQ(data, second_expected_encryped_data);
    ASSERT_NE(data, first_expected_encryped_data);
    ASSERT_NE(data, init_data);
    // Second decrypt
    symcrypt.decrypt(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_diversity)
{
    std::vector<uint8_t> data;
    data.reserve(256 + 9);
    data.resize(256, 0);
    cryp::symcrypt symcrypt(uuid::uuid("2689d9bd-9626-4023-8842-d244d48fe3bb"), rand::urng_u8<0, 255>(42));
    symcrypt.encrypt(data);
    ASSERT_EQ(data.capacity(), data.size());

    std::array<std::size_t, 256> byte_counters{ 0 };
    for (uint8_t byte : data)
        ++(byte_counters[byte]);
    auto counter_is_positive = [](const std::size_t& counter) { return counter > 0; };
    std::size_t number_of_positive_counters = std::ranges::count_if(byte_counters, counter_is_positive);
    ASSERT_GT(number_of_positive_counters, byte_counters.size() * 0.60);
}
