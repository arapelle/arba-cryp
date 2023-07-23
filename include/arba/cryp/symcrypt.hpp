#pragma once

#include <arba/cryp/config.hpp>
#include <arba/core/uuid.hpp>
#include <arba/core/random.hpp>
#include <vector>
#include <array>
#include <execution>

inline namespace arba
{
namespace cryp
{
namespace priv
{

template <bool = false>
struct default_execution_policy_
{
    inline constexpr static auto value = std::execution::seq;
};

template <>
struct default_execution_policy_<true>
{
    inline constexpr static auto value = std::execution::par;
};

}

class symcrypt
{
public:
    inline constexpr static uint8_t min_data_size = sizeof(core::uuid);
    using crypto_key = std::array<uint8_t, min_data_size>;
    using random_uint8_generator = std::function<uint8_t ()>;

private:
    inline constexpr static uint8_t min_data_size_1 = min_data_size + 1;
    static_assert(min_data_size_1 > min_data_size);
    using Offsets = std::array<uint8_t, 8>;

public:
    explicit symcrypt(const crypto_key& key, random_uint8_generator rng = core::urng_u8<255>());
    explicit symcrypt(const core::uuid& uuid, random_uint8_generator rng = core::urng_u8<255>());
    explicit symcrypt(const std::string_view &key, random_uint8_generator rng = core::urng_u8<255>());

    void encrypt(std::vector<uint8_t>& bytes);
    void decrypt(std::vector<uint8_t>& bytes);

    inline const crypto_key& key() const { return key_; }
    inline void set_key(const crypto_key& key) { key_ = key; }
    inline void set_key(const core::uuid& key) { set_key(crypto_key(key.data())); }
    void set_key(const std::string_view &key);

    inline const random_uint8_generator& random_number_generator() const { return random_number_generator_; }
    inline void set_random_number_generator(random_uint8_generator rng) { random_number_generator_ = std::move(rng); }

private:
    // add/remove data size
    void resize_before_encrypt_(std::vector<uint8_t>& bytes);
    void resize_after_decrypt_(std::vector<uint8_t>& bytes);

    // encrypt/decrypt bytes
    void encrypt_bytes_(std::vector<uint8_t>& bytes);
    void decrypt_bytes_(std::vector<uint8_t>& bytes);

    // encrypt/decrypt offsets
    void encrypt_and_stores_offsets_(std::vector<uint8_t>& bytes, const Offsets& offsets);
    void decrypt_and_retrieves_offsets_(std::vector<uint8_t>& bytes, Offsets& offsets);

    // encrypt/decrypt bytes
    template <class Iter>
    void encrypt_seq_(Iter begin, Iter end, const Offsets& offsets)
    {
        auto transform_byte = [&](uint8_t& byte)
        {
            encrypt_byte_(byte, crypto_offset_(&*begin, &byte, offsets));
        };
        std::for_each(priv::default_execution_policy_<has_tbb>::value, begin, end, transform_byte);
    }

    template <class Iter>
    void decrypt_seq_(Iter begin, Iter end, const Offsets& offsets)
    {
        auto transform_byte = [&](uint8_t& byte)
        {
            decrypt_byte_(byte, crypto_offset_(&*begin, &byte, offsets));
        };
        std::for_each(priv::default_execution_policy_<has_tbb>::value, begin, end, transform_byte);
    }

    uint8_t crypto_offset_(uint8_t* first_byte_iter, uint8_t* byte_iter, const Offsets& offsets);

    // encrypt/decrypt byte
    void encrypt_byte_(uint8_t& byte, uint8_t crypto_offset);
    void decrypt_byte_(uint8_t& byte, uint8_t crypto_offset);

    // utility
    std::array<uint8_t, 8> uint64_to_array8_(uint64_t integer);

private:
    crypto_key key_;
    random_uint8_generator random_number_generator_;
};

}
}
