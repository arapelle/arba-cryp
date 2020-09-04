# Concept

The purpose is to provide simple cryptographic algorithms in C++.

See [task board](https://app.gitkraken.com/glo/board/X1D-wj2bBQARup8C) for future updates and features.

# Install

## Requirements

Binaries:

- A C++20 compiler (ex: g++-10)
- CMake 3.16 or later

Libraries:

- [core](https://github.com/arapelle/core) 0.2 or later
- [Google Test](https://github.com/google/googletest) 1.10 or later (only for testing)

## Clone

```
git clone https://github.com/arapelle/cryp --recurse-submodules
```

## Quick Install

There is a cmake script at the root of the project which builds the library in *Release* mode and install it (default options are used).

```
cd /path/to/cryp
cmake -P cmake_quick_install.cmake
```

Use the following to quickly install a different mode.

```
cmake -DCMAKE_BUILD_TYPE=Debug -P cmake_quick_install.cmake
```

## Uninstall

There is a uninstall cmake script created during installation. You can use it to uninstall properly this library.

```
cd /path/to/installed-cryp/
cmake -P cmake_uninstall.cmake
```

# How to use

## Example - Generate a random word

```c++
#include <cryp/symcrypt.hpp>
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
```

## Example - Using *cryp* in a CMake project

See the [basic cmake project](https://github.com/arapelle/cryp/tree/master/example/basic_cmake_project) example, and more specifically the [CMakeLists.txt](https://github.com/arapelle/cryp/tree/master/example/basic_cmake_project/CMakeLists.txt) to see how to use *wgen* in your CMake projects.

# License

[MIT License](https://github.com/arapelle/cryp/blob/master/LICENSE.md) © cryp
