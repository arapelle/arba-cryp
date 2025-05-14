#include <arba/cryp/config.hpp>
#include <arba/cryp/symcrypt.hpp>
#include <arba/cryp/version.hpp>

#include <iostream>

template <std::ranges::input_range range_type>
void display_data(const std::string_view& message, const range_type& data)
{
    std::cout << message << ": [  ";
    for (const auto& value : data)
        printf("%02x  ", value);
    std::cout << "]" << std::endl;
}

int main()
{
    std::cout << "parallel_execution_is_available: " << cryp::parallel_execution_is_available << std::endl;

    cryp::symcrypt::crypto_key key{ 55, 197, 37, 199, 8, 246, 76, 209, 138, 255, 234, 62, 56, 234, 236, 135 };
    cryp::symcrypt symcrypt(key);
    std::vector<uint8_t> init_data{ 55, 79, 3, 220, 75, 225, 113, 112, 227, 138, 26, 140, 88, 111, 30, 107, 157, 45 };
    std::vector<uint8_t> data = init_data;
    display_data("                 data", data);
    symcrypt.encrypt(data);
    display_data("       encrypted data", data);
    symcrypt.decrypt(data);
    display_data("       decrypted data", data);
    symcrypt.encrypt(data);
    display_data("second encrypted data", data);
    symcrypt.decrypt(data);
    display_data("       decrypted data", data);

    std::cout << "TEST PACKAGE SUCCESS" << std::endl;
    return EXIT_SUCCESS;
}
