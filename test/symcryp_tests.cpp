#include <core/uuid.hpp>
#include <cryp/symcryp.hpp>
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

TEST(cryp_tests, test_construct_key)
{
    cryp::symcrypt::Key key{ 16, 216, 58, 6, 182, 126, 102, 212, 190, 60, 177, 6, 172, 106, 62, 46 };
    cryp::symcrypt::Key expected_key = key;
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), expected_key);
}

TEST(cryp_tests, test_construct_uuid)
{
    core::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), key.data());
}

TEST(cryp_tests, test_set_key_key)
{
    cryp::symcrypt::Key key{ 16, 216, 58, 6, 182, 126, 102, 212, 190, 60, 177, 6, 172, 106, 62, 46 };
    cryp::symcrypt symcrypt(key);
    cryp::symcrypt::Key new_key{ 254, 241, 196, 48, 101, 5, 236, 98, 32, 182, 176, 74, 60, 188, 4, 102 };
    ASSERT_NE(symcrypt.key(), new_key);
    symcrypt.set_key(new_key);
    ASSERT_EQ(symcrypt.key(), new_key);
}

TEST(cryp_tests, test_set_key_uuid)
{
    core::uuid key("a869ad09-1e02-452b-81c8-2efc5dfa24ad");
    cryp::symcrypt symcrypt(key);
    ASSERT_EQ(symcrypt.key(), key.data());
    core::uuid new_key("8defc670-716b-4242-9932-3009bf3e6ecc");
    ASSERT_NE(symcrypt.key(), new_key.data());
    symcrypt.set_key(new_key);
    ASSERT_EQ(symcrypt.key(), new_key.data());
}

TEST(cryp_tests, test_long_data)
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

TEST(cryp_tests, test_short_data)
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

TEST(cryp_tests, test_empty_data)
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

TEST(cryp_tests, test_zero_data)
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
    ASSERT_NE(data[0], data[1]);
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

TEST(cryp_tests, test_seq_data)
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

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
