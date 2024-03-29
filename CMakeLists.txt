cmake_minimum_required(VERSION 3.26)

# CMAKE INCLUDES

list(PREPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/external/cmake/)
include(CMakePrintHelpers)
include(cmtk/CppLibraryProject)

# CONFIGURATION

disable_in_source_build()
set_build_type_ifndef()

# C++ PROJECT

set(PROJECT_NAME "arba-cryp")
set(project_namespace "arba")
set(project_base_name "cryp")
set(PROJECT_VERSION 0.3.0)
project(${PROJECT_NAME}
        VERSION ${PROJECT_VERSION}
        DESCRIPTION "Small cryptographic library."
        HOMEPAGE_URL "https://github.com/arapelle/arba-cryp"
        LANGUAGES CXX)
message(STATUS "PROJECT : ${PROJECT_NAME} ${PROJECT_VERSION} ${CMAKE_BUILD_TYPE}")
include(CTest)

# C++ LIBRARY

## Execution policy parameter
set(${PROJECT_NAME}_DEFAULT_EXECUTION_POLICY "Parallel" CACHE STRING "Choose the default execution policy." FORCE)
set_property(CACHE ${PROJECT_NAME}_DEFAULT_EXECUTION_POLICY PROPERTY STRINGS "Parallel" "Sequenced")
if(${${PROJECT_NAME}_DEFAULT_EXECUTION_POLICY} STREQUAL "Parallel")
    find_package(TBB 2018 CONFIG)
endif()

## Generated/Configured headers:
generate_version_macro_header(generated_version_header
                              ${project_namespace}_${project_base_name}
                              ${project_namespace}/${project_base_name}/version.hpp)

configure_headers(configured_headers
    FILES include/arba/cryp/config.hpp.in
)

## Headers:
set(headers
    include/arba/cryp/symcrypt.hpp
)

# Sources:
set(sources
    src/symcrypt.cpp
)

## Add C++ library
add_cpp_library(
    SHARED ${PROJECT_NAME}
    STATIC ${PROJECT_NAME}-static
    BUILD_SHARED BUILD_arba-arba
    BUILD_STATIC BUILD_arba-arba-static
    HEADERS ${headers} ${configured_headers} ${generated_version_header}
    SOURCES ${sources}
    CXX_STANDARD 20
)

## Link C++ targets:
if(NOT TARGET arba-core)
    find_package(arba-core 0.14.0 REQUIRED CONFIG)
endif()
set(linked_libs arba-core)
if(TBB_FOUND)
    list(APPEND linked_libs TBB::tbb)
endif()
cpp_library_link_libraries(
    SHARED ${PROJECT_NAME}
    STATIC ${PROJECT_NAME}-static
    PUBLIC ${linked_libs}
)

## Install C++ library:
install_cpp_library(
    SHARED ${PROJECT_NAME}
    STATIC ${PROJECT_NAME}-static
    EXPORT ${PROJECT_NAME}-targets
)

## Install project package
install_library_package(${PROJECT_NAME} INPUT_PACKAGE_CONFIG_FILE cmake/config/package-config.cmake.in)
install_uninstall_script(${PROJECT_NAME} FILENAME uninstall.cmake)

## Add examples:
option_or_set_ifdef(BUILD_${PROJECT_NAME}_EXAMPLES "Build ${PROJECT_NAME} examples or not" OFF BUILD_arba-arba_EXAMPLES)
if(BUILD_${PROJECT_NAME}_EXAMPLES)
    add_subdirectory(example)
endif()

## Add tests:
option_or_set_ifdef(BUILD_${PROJECT_NAME}_TESTS "Build ${PROJECT_NAME} tests or not" OFF BUILD_arba-arba_TESTS)
option(BUILD_${PROJECT_NAME}_TESTS "Build ${PROJECT_NAME} tests or not" OFF)
if(BUILD_${PROJECT_NAME}_TESTS AND BUILD_TESTING)
    add_subdirectory(test)
endif()
