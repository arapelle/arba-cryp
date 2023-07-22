#include <arba/core/hash.hpp>
#include <arba/cryp/symcrypt.hpp>
#include <gtest/gtest.h>
#include <ranges>
#include <cstdlib>

auto long_data()
{
    return std::vector<uint8_t>{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
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
    std::cout << "[  ";
    for (const auto& value : data)
        printf("%02x  ", value);
    std::cout << "]" << std::endl;
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
    core::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), key.data());
}

TEST(symcrypt_tests, test_construct_string_view)
{
    std::string_view key("my password 01A%^o");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), core::neutral_murmur_hash_array_16(key.data(), key.length()));
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
    core::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), key.data());
    core::uuid new_key("8defc670-716b-4242-9932-3009bf3e6ecc");
    ASSERT_NE(symcrypt.key(), new_key.data());
    symcrypt.set_key(new_key);
    ASSERT_EQ(symcrypt.key(), new_key.data());
}

TEST(symcrypt_tests, test_set_key_string_view)
{
    std::string_view key("my password 01A%^o");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), core::neutral_murmur_hash_array_16(key.data(), key.length()));
    std::string_view new_key("8defc670-716b-4242-9932-3009bf3e6ecc");
    ASSERT_NE(symcrypt.key(), core::neutral_murmur_hash_array_16(new_key.data(), new_key.length()));
    symcrypt.set_key(new_key);
    ASSERT_EQ(symcrypt.key(), core::neutral_murmur_hash_array_16(new_key.data(), new_key.length()));
}

TEST(symcrypt_tests, test_long_data)
{
    core::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    std::vector<uint8_t> init_data = long_data();
    std::vector<uint8_t> data = init_data;
    display_data(data);
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    std::vector<uint8_t> aux_data = data;
    display_data(data);
    ASSERT_NE(data, init_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    display_data(data);
    ASSERT_NE(data, aux_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_short_data)
{
    core::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    std::vector<uint8_t> init_data = short_data();
    std::vector<uint8_t> data = init_data;
    display_data(data);
    ASSERT_LT(data.size(), cryp::symcrypt::min_data_size);
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    display_data(data);
    ASSERT_GT(data.size(), cryp::symcrypt::min_data_size);
    std::vector<uint8_t> aux_data = data;
    ASSERT_NE(data, init_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    display_data(data);
    ASSERT_NE(data, aux_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_empty_data)
{
    core::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    std::vector<uint8_t> init_data = empty_data();
    std::vector<uint8_t> data = init_data;
    display_data(data);
    ASSERT_TRUE(data.empty());
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    std::vector<uint8_t> aux_data = data;
    display_data(data);
    ASSERT_NE(data, init_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    display_data(data);
    ASSERT_NE(data, aux_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_zero_data)
{
    core::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    std::vector<uint8_t> init_data = zero_data();
    std::vector<uint8_t> data = init_data;
    display_data(data);
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    std::vector<uint8_t> aux_data = data;
    display_data(data);
    ASSERT_NE(data, init_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    display_data(data);
    ASSERT_NE(data, aux_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_seq_data)
{
    core::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    std::vector<uint8_t> init_data = seq_data();
    std::vector<uint8_t> data = init_data;
    display_data(data);
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    std::vector<uint8_t> aux_data = data;
    display_data(data);
    ASSERT_NE(data, init_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
    symcrypt.encrypt(data);
    display_data(data);
    ASSERT_NE(data, aux_data);
    symcrypt.decrypt(data);
    display_data(data);
    ASSERT_EQ(data, init_data);
}

TEST(symcrypt_tests, test_diversity)
{
    std::vector<uint8_t> data;
    data.reserve(256 + 9);
    data.resize(256, 0);
    cryp::symcrypt symcrypt(core::uuid("2689d9bd-9626-4023-8842-d244d48fe3bb"));
    symcrypt.encrypt(data);
    ASSERT_EQ(data.capacity(), data.size());

    std::vector<std::size_t> byte_counters(256, 0);
    for (uint8_t byte : data)
        ++(byte_counters[byte]);
    auto counter_is_positive = [](const std::size_t& counter){ return counter > 0; };
    std::size_t number_of_positive_counters = std::ranges::count_if(byte_counters, counter_is_positive);
    ASSERT_GT(number_of_positive_counters, byte_counters.size()/2);
}
