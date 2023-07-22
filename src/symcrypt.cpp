#include <arba/cryp/symcrypt.hpp>
#include <arba/core/hash.hpp>
#include <span>
#include <bit>
#include <experimental/random>

namespace cryp
{
symcrypt::symcrypt(const crypto_key& key)
    : key_(key)
{}

symcrypt::symcrypt(const core::uuid& uuid)
    : key_(uuid.data())
{}

symcrypt::symcrypt(const std::string_view& key)
    : key_(core::neutral_murmur_hash_array_16(key.data(), key.length()))
{}

void symcrypt::set_key(const std::string_view& key)
{
    key_ = core::neutral_murmur_hash_array_16(key.data(), key.length());
}

void symcrypt::encrypt(std::vector<uint8_t>& bytes)
{
    resize_before_encrypt_(bytes);
    encrypt_bytes_(bytes);
}

void symcrypt::decrypt(std::vector<uint8_t>& bytes)
{
    decrypt_bytes_(bytes);
    resize_after_decrypt_(bytes);
}

// add/remove data size
void symcrypt::resize_before_encrypt_(std::vector<uint8_t>& bytes)
{
    uint8_t bytes_size = min_data_size_1;
    if (bytes.size() <= min_data_size) [[unlikely]]
    {
        // The data are resized so that empty or very small data cannot be guessed.
        bytes_size = static_cast<uint8_t>(bytes.size());
        for (; bytes.size() < min_data_size; )
            bytes.push_back(rand_uint8());
    }
    // Size information is stored at the end of data.
    bytes.push_back(bytes_size);
}

void symcrypt::resize_after_decrypt_(std::vector<uint8_t>& bytes)
{
    // Size information is retrieved, and data is resized consequently.
    uint8_t bytes_size = bytes.back();
    if (bytes_size <= min_data_size) [[unlikely]]
        bytes.resize(bytes_size);
    else
        bytes.pop_back();
}

// encrypt/decrypt bytes
void symcrypt::encrypt_bytes_(std::vector<uint8_t>& bytes)
{
    // Get offsets randomly so that twice encryption of the
    // same data do not generate the same byte sequence.
    Offsets offs = rand_offsets();
    // Encrypt the byte sequence.
    encrypt_seq_(bytes.begin(), bytes.end(), offs);
    // The offsets must be appended to the generated byte sequence
    // as it cannot be guessed by the decrypter.
    encrypt_and_stores_offsets_(bytes, offs);
}

void symcrypt::decrypt_bytes_(std::vector<uint8_t>& bytes)
{
    // Get the offsets, and remove them from the byte sequence to decrypt.
    Offsets offs;
    decrypt_and_retrieves_offsets_(bytes, offs);
    // Decrypt the byte sequence.
    decrypt_seq_(bytes.begin(), bytes.end(), offs);
}

// encrypt/decrypt offsets
void symcrypt::encrypt_and_stores_offsets_(std::vector<uint8_t>& bytes, const Offsets& offsets)
{
    uint64_t key_hash = core::neutral_murmur_hash_64(key_.data(), min_data_size);
    std::array key_hash_bytes = uint64_to_array8(key_hash);

    bytes.reserve(bytes.size() + offsets.size());
    for (auto key_iter = key_hash_bytes.begin(); const uint8_t& offset : offsets)
    {
        bytes.push_back(offset + *key_iter);
        ++key_iter;
    }
}

void symcrypt::decrypt_and_retrieves_offsets_(std::vector<uint8_t>& bytes, Offsets& offsets)
{
    uint64_t key_hash = core::neutral_murmur_hash_64(key_.data(), min_data_size);
    std::array key_hash_bytes = uint64_to_array8(key_hash);
    std::span offsets_span(&*(bytes.end() - offsets.size()), offsets.size());

    auto key_iter = key_hash_bytes.begin();
    auto span_iter = offsets_span.begin();
    for (uint8_t& offset : offsets)
    {
        offset = *span_iter - *key_iter;
        ++span_iter;
        ++key_iter;
    }
    bytes.resize(bytes.size() - offsets.size());
}

uint8_t symcrypt::crypto_offset_(uint8_t* first_byte_iter, uint8_t* byte_iter, const Offsets& offsets)
{
    std::size_t byte_index = byte_iter - first_byte_iter;
    uint8_t key_byte = key_[byte_index % min_data_size];
    std::size_t offset_index = key_.back() + byte_index + (byte_index / (offsets.size()+1));
    uint8_t offset = offsets[offset_index % offsets.size()]; // random start offset
    offset += static_cast<uint8_t>(byte_index % 256); // avoid repetition
    offset += key_byte;
    return offset;
}

// encrypt/decrypt byte
void symcrypt::encrypt_byte_(uint8_t& byte, uint8_t crypto_offset)
{
    uint8_t aux = byte + crypto_offset; // Add an offset to the byte,
    byte = std::rotl(aux, std::popcount(aux) * std::popcount(crypto_offset)); // bitwise left-rotate the byte.
}

void symcrypt::decrypt_byte_(uint8_t& byte, uint8_t crypto_offset)
{
    // bitwise right-rotate the byte and remove the offset.
    byte = std::rotr(byte, std::popcount(byte) * std::popcount(crypto_offset)) - crypto_offset;
}

// utility
uint8_t symcrypt::rand_uint8()
{
    return static_cast<uint8_t>(std::experimental::randint(0, 127)) + 1;
}

symcrypt::Offsets symcrypt::rand_offsets()
{
    uint64_t rand_val = std::experimental::randint(std::numeric_limits<uint64_t>::min(),
                                                   std::numeric_limits<uint64_t>::max());
    return uint64_to_array8(rand_val);
}

std::array<uint8_t, 8> symcrypt::uint64_to_array8(uint64_t integer)
{
    std::array<uint8_t, 8> array;
    for (uint8_t& byte : array)
    {
        byte = integer % 256;
        integer /= 256;
    }
    return array;
}
}
