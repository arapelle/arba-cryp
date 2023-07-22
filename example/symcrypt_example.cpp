#include <arba/cryp/symcrypt.hpp>
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
    core::uuid key("37c525c7-08f6-4cd1-8aff-ea3e38eaec87");
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

    return EXIT_SUCCESS;
}
