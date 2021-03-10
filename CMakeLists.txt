
cmake_minimum_required(VERSION 2.8.12)

# automagically detect if we should cross-compile
if(DEFINED ENV{TOOLCHAIN})
    set(CMAKE_C_COMPILER	$ENV{TOOLCHAIN}gcc)
    set(CMAKE_CXX_COMPILER	$ENV{TOOLCHAIN}g++)
    set(CMAKE_AR	"$ENV{TOOLCHAIN}ar" CACHE FILEPATH "CW archiver" FORCE)
endif()

set(APP seapath-test-tools)

project(${APP})
ENABLE_TESTING()

option(BUILD_KERNEL "Build the kernel seapath test binaries" ON)
option(BUILD_DPDK "Build the DPDK seapath test binaries" ON)


if(BUILD_KERNEL)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/kernel)
endif(BUILD_KERNEL)

if(BUILD_DPDK)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/dpdk)
endif(BUILD_DPDK)
