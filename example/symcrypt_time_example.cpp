#include <arba/cryp/symcrypt.hpp>
#include <chrono>
#include <experimental/random>
#include <iostream>

using Duration = std::chrono::duration<float, ::std::chrono::milliseconds::period>;
using Clock = std::chrono::steady_clock;
using Time_point = std::chrono::time_point<Clock>;

int main()
{
    core::uuid key("37c525c7-08f6-4cd1-8aff-ea3e38eaec87");
    cryp::symcrypt symcrypt(key);
    std::vector<uint8_t> data;
    std::size_t data_size = 1024*1024*1024; // 1Gb
    data.reserve(data_size + 9);
    data.resize(data_size);

    //-----

    Time_point start_time_point;
    Duration duration;

    std::cout << "Chrono '" << "generate data" <<  "' start!" << std::endl;
    start_time_point = Clock::now();
    std::ranges::generate(data, [](){ return std::experimental::randint(0,256); });
    std::vector init_data = data;
    duration = std::chrono::duration_cast<Duration>(Clock::now() - start_time_point);
    std::cout << "Chrono '" << "generate data" <<  "' = " << duration.count() << "ms" << std::endl;

    std::cout << "Chrono '" << "encrypt" <<  "' start!" << std::endl;
    start_time_point = Clock::now();
    symcrypt.encrypt(data);
    duration = std::chrono::duration_cast<Duration>(Clock::now() - start_time_point);
    std::cout << "Chrono '" << "encrypt" <<  "' = " << duration.count() << "ms" << std::endl;
    std::cout << "data == init_data: " << std::boolalpha << (data == init_data) << std::endl;

    std::cout << "Chrono '" << "decrypt" <<  "' start!" << std::endl;
    start_time_point = Clock::now();
    symcrypt.decrypt(data);
    duration = std::chrono::duration_cast<Duration>(Clock::now() - start_time_point);
    std::cout << "Chrono '" << "decrypt" <<  "' = " << duration.count() << "ms" << std::endl;
    std::cout << "data == init_data: " << std::boolalpha << (data == init_data) << std::endl;

    return EXIT_SUCCESS;
}
