cmake_minimum_required(VERSION 3.18)

list(PREPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/)

include(CMakePrintHelpers)
include(cmtk/CppLibraryProject)

#-----
# PROJECT

check_cmake_binary_dir()
set_build_type_if_undefined()

#-----
# C++ PROJECT

project(cryp
        VERSION 0.2.4
        DESCRIPTION "Small cryptographic library."
        HOMEPAGE_URL "https://github.com/arapelle/cryp"
        LANGUAGES CXX)

message(STATUS "BUILD   : ${CMAKE_BUILD_TYPE}")
message(STATUS "CPPCOMP : ${CMAKE_CXX_COMPILER} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "PROJECT : ${PROJECT_NAME} ${PROJECT_VERSION}")

#-----
include(CTest)

# Project options
library_build_options(${PROJECT_NAME} STATIC SHARED EXAMPLE TEST)

# Headers:
set(headers
include/cryp/symcrypt.hpp
)

# Sources:
set(sources
src/symcrypt.cpp
)

# Find TBB if wanted
set(${PROJECT_NAME}_DEFAULT_EXECUTION_POLICY "Parallel" CACHE STRING "Choose the default execution policy." FORCE)
set_property(CACHE ${PROJECT_NAME}_DEFAULT_EXECUTION_POLICY PROPERTY STRINGS "Parallel" "Sequenced")
if(${${PROJECT_NAME}_DEFAULT_EXECUTION_POLICY} STREQUAL "Parallel")
    find_package(TBB 2018 CONFIG)
endif()

# Add C++ library
add_cpp_library(${PROJECT_NAME} ${PROJECT_NAME}_BUILD_SHARED_LIB ${PROJECT_NAME}_BUILD_STATIC_LIB
    SHARED ${PROJECT_NAME}
    STATIC ${PROJECT_NAME}-static
    NAMESPACE arba::
    CXX_STANDARD 20
    INCLUDE_DIRECTORIES include
    INPUT_VERSION_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include.in/version.hpp"
    OUTPUT_VERSION_HEADER "version.hpp"
    HEADERS ${headers}
    SOURCES ${sources}
    BUILT_TARGETS project_targets
    )

if(NOT TARGET arba::core)
    find_package(core 0.3.2 REQUIRED CONFIG)
endif()
cpp_library_targets_link_libraries(${PROJECT_NAME} PUBLIC arba::core)
if(TBB_FOUND)
    cpp_library_targets_link_libraries(${PROJECT_NAME} PUBLIC TBB::tbb)
endif()

# Install C++ library
install_cpp_library_targets(${PROJECT_NAME}
                            TARGETS ${project_targets}
                            INCLUDE_DIRECTORIES "include/${PROJECT_NAME}"
                            NAMESPACE arba::
                            )

# Install package
install_package(${PROJECT_NAME}
                INPUT_PACKAGE_CONFIG_FILE ${PROJECT_NAME}-config.cmake.in
                EXPORT_NAMES ${PROJECT_NAME})

if(${PROJECT_NAME}_BUILD_EXAMPLES)
    add_subdirectory(example)
endif()

if(${PROJECT_NAME}_BUILD_TESTS AND BUILD_TESTING)
    add_subdirectory(test)
endif()

#-----
