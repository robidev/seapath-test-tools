# Copyright (C) 2021, Alliander (http://www.alliander.com)
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 2.8.12)

# automagically detect if we should cross-compile
if(DEFINED ENV{TOOLCHAIN})
    set(CMAKE_C_COMPILER	$ENV{TOOLCHAIN}gcc)
    set(CMAKE_CXX_COMPILER	$ENV{TOOLCHAIN}g++)
    set(CMAKE_AR	"$ENV{TOOLCHAIN}ar" CACHE FILEPATH "CW archiver" FORCE)
endif()

set(APP kern-smv9-2-publisher)

project(${APP})

ENABLE_TESTING()

# feature checks
include(CheckLibraryExists)
check_library_exists(rt clock_gettime "time.h" CONFIG_SYSTEM_HAS_CLOCK_GETTIME)

# check if we are on a little or a big endian
include (TestBigEndian)
test_big_endian(PLATFORM_IS_BIGENDIAN)


set(open_server_SRCS  kern-smv9-2-publisher.c)

add_executable(${APP} ${open_server_SRCS})
target_link_libraries(${APP} m)

install ( TARGETS ${APP} DESTINATION bin)

