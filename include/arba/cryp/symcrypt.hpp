#pragma once

#include <arba/rand/urng.hpp>
#include <arba/uuid/uuid.hpp>

#include <array>
#include <functional>
#include <vector>

inline namespace arba
{
namespace cryp
{
class symcrypt
{
public:
    inline constexpr static uint8_t min_data_size = sizeof(uuid::uuid);
    using crypto_key = std::array<uint8_t, min_data_size>;
    using random_uint8_generator = std::function<uint8_t()>;

private:
    inline constexpr static uint8_t min_data_size_1 = min_data_size + 1;
    static_assert(min_data_size_1 > min_data_size);
    using offsets = std::array<uint8_t, 8>;

public:
    explicit symcrypt(const crypto_key& key, random_uint8_generator rng = rand::urng_u8<0, 255>{});
    [[deprecated]] explicit symcrypt(const uuid::uuid& uuid, random_uint8_generator rng = rand::urng_u8<0, 255>{});
    explicit symcrypt(const std::string_view& key, random_uint8_generator rng = rand::urng_u8<0, 255>{});

    void encrypt(std::vector<uint8_t>& bytes, bool use_parallel_execution = true);
    void decrypt(std::vector<uint8_t>& bytes, bool use_parallel_execution = true);

    inline const crypto_key& key() const { return key_; }
    inline void set_key(const crypto_key& key) { key_ = key; }
    [[deprecated]] inline void set_key(const uuid::uuid& key) { set_key(crypto_key(key.data())); }
    void set_key(const std::string_view& key);

    inline const random_uint8_generator& random_number_generator() const { return random_number_generator_; }
    inline random_uint8_generator& random_number_generator() { return random_number_generator_; }

private:
    // add/remove data size
    void resize_before_encrypt_(std::vector<uint8_t>& bytes);
    void resize_after_decrypt_(std::vector<uint8_t>& bytes);

    // encrypt/decrypt bytes
    void encrypt_bytes_(std::vector<uint8_t>& bytes, bool use_parallel_execution);
    void decrypt_bytes_(std::vector<uint8_t>& bytes, bool use_parallel_execution);

    // encrypt/decrypt offsets
    void encrypt_and_stores_offsets_(std::vector<uint8_t>& bytes, const offsets& offs);
    void decrypt_and_retrieves_offsets_(std::vector<uint8_t>& bytes, offsets& offs);

    // encrypt/decrypt bytes
    void encrypt_seq_(std::vector<uint8_t>::iterator begin, std::vector<uint8_t>::iterator end, const offsets& offs,
                      bool use_parallel_execution);
    void decrypt_seq_(std::vector<uint8_t>::iterator begin, std::vector<uint8_t>::iterator end, const offsets& offs,
                      bool use_parallel_execution);

    uint8_t crypto_offset_(uint8_t* first_byte_iter, uint8_t* byte_iter, const offsets& off);
    std::pair<uint8_t, int> crypto_modifiers_(uint8_t *first_byte_iter, uint8_t *byte_iter, const offsets& offs);

    // utility
    std::array<uint8_t, 8> uint64_to_array8_(uint64_t integer);

private:
    crypto_key key_;
    random_uint8_generator random_number_generator_;
    std::size_t start__;
};

} // namespace cryp
} // namespace arba
