cmake_minimum_required(VERSION 3.16)

project(basic_cmake_project)

add_executable(${PROJECT_NAME} main.cpp)
# Find package cryp:
find_package(cryp 0.2.4 CONFIG REQUIRED)
# Use cryp release shared target:
target_link_libraries(${PROJECT_NAME} PRIVATE arba::cryp)
# Use cryp release static target:
#target_link_libraries(${PROJECT_NAME} PRIVATE arba::cryp-static)
