cmake_minimum_required(VERSION 3.16)

project(testapp)

# Project-wide build flags
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(realm-core)

set(REALM_BUILD_LIB_ONLY ON)
set(REALM_ENABLE_SYNC)
set(REALM_NO_TESTS)
set(REALM_ENABLE_ENCRYPTION ON)
set(REALM_INSTALL_LIBEXECDIR)

add_subdirectory(src)

set(CMAKE_OSX_SYSROOT ${CMAKE_OSX_SYSROOT_PATH})
