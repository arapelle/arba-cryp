cmake_minimum_required(VERSION 3.26)

# EXTERNAL DEPENDENCIES

add_subdirectory(external)

# CMAKE INCLUDES

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/external/cmake/)
include(CMakePrintHelpers)
include(cmtk/CppLibraryProject)

# CONFIGURATION

disable_in_source_build()
set_build_type_ifndef()

# C++ PROJECT

set_project_name(NAMESPACE "arba" BASE_NAME "cryp")
string(TIMESTAMP configure_datetime "%Y%m%d-%H%M%S")
set_project_semantic_version("0.4.0" PRE_RELEASE "dev" BUILD_METADATA "${configure_datetime}")

project(${PROJECT_NAME}
        VERSION ${PROJECT_VERSION}
        DESCRIPTION "A C++ library providing cryptographic algorithms."
        HOMEPAGE_URL "https://github.com/arapelle/arba-cryp"
        LANGUAGES CXX)
message(STATUS "PROJECT : ${PROJECT_NAME} ${PROJECT_SEMANTIC_VERSION} ${CMAKE_BUILD_TYPE}")

# C++ LIBRARY

option(${PROJECT_UPPER_VAR_NAME}_PARALLEL_EXECUTION "Make parallel execution available for arba-cryp algorithms." Off)

## Generated/Configured headers:
if(${PROJECT_UPPER_VAR_NAME}_PARALLEL_EXECUTION)
    set(ARBA_CRYP_PARALLEL_EXECUTION_IS_AVAILABLE 1)
else()
    set(ARBA_CRYP_PARALLEL_EXECUTION_IS_AVAILABLE 0)
endif()
configure_headers(configured_headers
    FILES
        include/${PROJECT_NAMESPACE}/${PROJECT_BASE_NAME}/version.hpp.in
        include/${PROJECT_NAMESPACE}/${PROJECT_BASE_NAME}/config.hpp.in
)

## Headers:
set(headers
    include/arba/cryp/symcrypt.hpp
)

## Sources:
set(sources
    src/arba/cryp/symcrypt.cpp
)

## Add C++ library:
shared_or_static_option(${PROJECT_UPPER_VAR_NAME}_LIBRARY_TYPE "SHARED")
if("${${PROJECT_UPPER_VAR_NAME}_LIBRARY_TYPE}" STREQUAL "SHARED")
  set(LIBRARY_TYPE_POSTFIX "")
  set(PROJECT_TARGET_NAME "${PROJECT_NAME}")
else()
  set(LIBRARY_TYPE_POSTFIX "-static")
  set(PROJECT_TARGET_NAME "${PROJECT_NAME}${LIBRARY_TYPE_POSTFIX}")
endif()

add_cpp_library(${PROJECT_TARGET_NAME} ${${PROJECT_UPPER_VAR_NAME}_LIBRARY_TYPE}
  HEADERS ${headers} ${configured_headers}
  SOURCES ${sources}
  CXX_STANDARD 20
  DEFAULT_WARNING_OPTIONS
)
add_library("${PROJECT_NAMESPACE}::${PROJECT_BASE_NAME}${LIBRARY_TYPE_POSTFIX}" ALIAS ${PROJECT_TARGET_NAME})

if(${${PROJECT_UPPER_VAR_NAME}_PARALLEL_EXECUTION})
    target_compile_definitions(${PROJECT_TARGET_NAME} PRIVATE -D${PROJECT_UPPER_VAR_NAME}_PARALLEL_EXECUTION_IS_AVAILABLE=1)
    find_package(TBB 2018 CONFIG REQUIRED)
    target_link_libraries(${PROJECT_TARGET_NAME}
        PUBLIC
            TBB::tbb
    )
endif()

## Link C++ targets:
find_package(arba-uuid 0.2.0 REQUIRED CONFIG)
target_link_libraries(${PROJECT_TARGET_NAME}
    PUBLIC
        arba::uuid
)

## Add tests:
add_test_subdirectory_if_build(test)

## Add examples:
add_example_subdirectory_if_build(example)

# C++ INSTALL

## Install C++ library:
install_cpp_libraries(TARGETS ${PROJECT_TARGET_NAME} EXPORT ${PROJECT_NAME}-targets)

## Install project package
install_library_package(${PROJECT_NAME} INPUT_PACKAGE_CONFIG_FILE cmake/config/package-config.cmake.in)
install_uninstall_script(${PROJECT_NAME})
