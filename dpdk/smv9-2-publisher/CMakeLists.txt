# Copyright (C) 2021, Alliander (http://www.alliander.com)
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 2.8.12)

# automagically detect if we should cross-compile
if(DEFINED ENV{TOOLCHAIN})
    set(CMAKE_C_COMPILER	$ENV{TOOLCHAIN}gcc)
    set(CMAKE_CXX_COMPILER	$ENV{TOOLCHAIN}g++)
    set(CMAKE_AR	"$ENV{TOOLCHAIN}ar" CACHE FILEPATH "CW archiver" FORCE)
endif()

set(APP dpdk-smv9-2-publisher)

project(${APP})

ENABLE_TESTING()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu11 -mavx2")

SET(CMAKE_EXE_LINKER_FLAGS "-static")

# check if we are on a little or a big endian
include (TestBigEndian)
test_big_endian(PLATFORM_IS_BIGENDIAN)

set(publisher_SRCS
   dpdk-smv9-2-publisher.c
)

SET(DPDK_LIBS
	rte_net      rte_ethdev       rte_distributor 	 rte_mbuf      rte_pmd_bond       rte_kni              rte_pmd_ring     rte_power  
	rte_acl      rte_eal          rte_kvargs   	 rte_mempool   rte_mempool_ring	  rte_pmd_e1000        rte_pmd_virtio   rte_ring
	rte_cfgfile  rte_hash         rte_lpm      	 rte_meter     rte_pmd_i40e   	  rte_sched        rte_timer
	rte_cmdline  rte_ip_frag      rte_pipeline 	 rte_pmd_ixgbe rte_mempool_stack               rte_table        rte_pmd_bnxt
	rte_pmd_ena  rte_pmd_nfp      rte_stack          rte_bus_vdev  rte_bus_pci        rte_pci              rte_cryptodev
)

SET(ALL_LIBS
	-Wl,--whole-archive -Wl,--start-group ${DPDK_LIBS} -Wl,--end-group -Wl,--no-whole-archive pthread dl rt m numa
)

add_executable(${APP}  ${publisher_SRCS})
target_link_libraries(${APP}  ${ALL_LIBS})

install ( TARGETS ${APP} DESTINATION bin)


