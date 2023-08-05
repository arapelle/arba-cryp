cmake_minimum_required(VERSION 3.26)

project(basic_cmake_project)

add_executable(${PROJECT_NAME} main.cpp)
add_executable(${PROJECT_NAME}-static main.cpp)
# Find package arba-cryp:
find_package(arba-cryp 0.3.0 CONFIG REQUIRED)
# Use arba-cryp release shared target:
target_link_libraries(${PROJECT_NAME} PRIVATE arba-cryp)
# Use arba-cryp release static target:
target_link_libraries(${PROJECT_NAME}-static PRIVATE arba-cryp-static)
