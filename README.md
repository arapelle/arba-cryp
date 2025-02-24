# Concept

A C++ library providing cryptographic algorithms.

# Install

## Requirements

Binaries:
- A C++20 compiler (ex: g++-14)
- CMake 3.26 or later

Libraries:
- [TBB](https://github.com/oneapi-src/oneTBB) 2018 or later (only if you want to use parallel execution)

Testing Libraries (optional):
- [Google Test](https://github.com/google/googletest) 1.14 or later (optional)

## Clone

```
git clone https://github.com/arapelle/arba-cryp
```

## Use with `conan`

Create the conan package.
```
conan create . --build=missing -c
```
Add a requirement in your conanfile project file.
```python
    def requirements(self):
        self.requires("arba-cryp/0.4.0")
```

## Quick Install 

There is a cmake script at the root of the project which builds the library in *Release* mode and install it (default options are used).

```
cd /path/to/arba-cryp
cmake -P cmake/scripts/quick_install.cmake
```

Use the following to quickly install a different mode.

```
cmake -P cmake/scripts/quick_install.cmake -- TESTS BUILD Debug DIR /tmp/local
```

## Uninstall

There is a uninstall cmake script created during installation. You can use it to uninstall properly this library.

```
cd /path/to/installed-arba-cryp/
cmake -P uninstall.cmake
```

# How to use

## Example - To measure time to encrypt and decrypt

```c++
#include <arba/cryp/symcrypt.hpp>

#include <arba/rand/rand.hpp>

#include <algorithm>
#include <chrono>
#include <iostream>

using Duration = std::chrono::duration<float, ::std::chrono::milliseconds::period>;
using Clock = std::chrono::steady_clock;
using Time_point = std::chrono::time_point<Clock>;

int main()
{
    uuid::uuid key("37c525c7-08f6-4cd1-8aff-ea3e38eaec87");
    cryp::symcrypt symcrypt(key);
    std::vector<uint8_t> data;
    std::size_t data_size = 1024 * 1024 * 1024; // 1Gb
    data.reserve(data_size + 9);
    data.resize(data_size);

    //-----

    Time_point start_time_point;
    Duration duration;

    std::cout << "Chrono '" << "generate data" << "' start!" << std::endl;
    start_time_point = Clock::now();
    std::ranges::generate(data, []() { return rand::rand_u8(); });
    std::vector init_data = data;
    duration = std::chrono::duration_cast<Duration>(Clock::now() - start_time_point);
    std::cout << "Chrono '" << "generate data" << "' = " << duration.count() << "ms" << std::endl;

    std::cout << "Chrono '" << "encrypt" << "' start!" << std::endl;
    start_time_point = Clock::now();
    symcrypt.encrypt(data);
    duration = std::chrono::duration_cast<Duration>(Clock::now() - start_time_point);
    std::cout << "Chrono '" << "encrypt" << "' = " << duration.count() << "ms" << std::endl;
    std::cout << "data == init_data: " << std::boolalpha << (data == init_data) << std::endl;

    std::cout << "Chrono '" << "decrypt" << "' start!" << std::endl;
    start_time_point = Clock::now();
    symcrypt.decrypt(data);
    duration = std::chrono::duration_cast<Duration>(Clock::now() - start_time_point);
    std::cout << "Chrono '" << "decrypt" << "' = " << duration.count() << "ms" << std::endl;
    std::cout << "data == init_data: " << std::boolalpha << (data == init_data) << std::endl;

    return EXIT_SUCCESS;
}
```

# License

[MIT License](./LICENSE.md) © arba-cryp
