#include <cryp/symcrypt.hpp>
#include <arba/cryp/version.hpp>
#include <iostream>

int main()
{
    core::uuid id("ced1cc82-37ea-450f-a5ec-00e3c10a00f2");
    cryp::symcrypt symcrypt(id);
    std::cout << ARBA_CRYP_VERSION << std::endl;
    return EXIT_SUCCESS;
}
