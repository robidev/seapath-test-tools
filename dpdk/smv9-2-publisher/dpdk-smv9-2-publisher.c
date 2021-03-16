/* # Copyright (C) 2021, Alliander (http://www.alliander.com)
     SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <time.h>  /* for struct timespec */

#include <sys/types.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 1

#define LEN 128

uint8_t buf[LEN] = { //                       start-addr
0x01, 0x0c, 0xcd, 0x01, 0x00, 0x03,//dest     0
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,//source   6

0x81, 0x00, //vlan ETHtype                    12
0x80, 0x01, //vlan properties                 14

0x88, 0xba, //SMV type                        16
0x40, 0x00, //appid = 0x4000                  18
0x00, 0x6e, //length = 110                    20
0x00, 0x00, //reserved 1 = 0                  22
0x00, 0x00, //reserved 2 = 0                  24
0x60, 0x64, //ASN1 frame                      26
0x80, 0x01, //savPDU                          28
0x01,       //no ASDU = 1                     30

0xa2, 0x5f, //seqASDU = 1 item                31
0x30, 0x5d, // ASDU struct                    33
0x80, 0x02, // ASN1 length 2                  35
'A' , '1' , // svID                           37
0x82, 0x02, // ASN1 length 2                  39
0x00, 0x00, // smpCnt = 0                     41
0x83, 0x04, // ASN1 length 4                  43
0x00, 0x00, 0x00, 0x01, //confRev = 1         45
0x84, 0x08, // ASN1 length 8                  49
0x60, 0x19, 0x2d, 0x52, 0xe1, 0x47, 0xae, 0x0a, // RefrTM (seconds since epoch)   51
0x85, 0x01, // ASN1 length 1                  59
0x00,       // smpSynch = none                61
0x87, 0x40, // ASN1 length 64                 62

0x00, 0x00, 0x00, 0x00, //v1                  64
0x00, 0x00, 0x00, 0x00, //qv1                 68
0x00, 0x00, 0x00, 0x00, //v2                  72
0x00, 0x00, 0x00, 0x00, //qv2                 76
0x00, 0x00, 0x00, 0x00, //v3                  80
0x00, 0x00, 0x00, 0x00, //qv3                 84
0x00, 0x00, 0x00, 0x00, //v4                  88
0x00, 0x00, 0x00, 0x00, //qv4                 92
0x00, 0x00, 0x00, 0x00, //a1                  96
0x00, 0x00, 0x00, 0x00, //qa1                 100
0x00, 0x00, 0x00, 0x00, //a2                  104
0x00, 0x00, 0x00, 0x00, //qa2                 108
0x00, 0x00, 0x00, 0x00, //a3                  112
0x00, 0x00, 0x00, 0x00, //qa3                 116
0x00, 0x00, 0x00, 0x00, //a4                  120
0x00, 0x00, 0x00, 0x00  //aq4                 124
}; //                                         128


struct rte_mempool *mbuf_pool;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

//
// Initializes a given port using global settings and with the RX buffers
// * coming from the mbuf_pool passed as a parameter.
 
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	// Configure the Ethernet device. 
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	// Allocate and set up 1 RX queue per Ethernet port. 
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	// Allocate and set up 1 TX queue per Ethernet port. 
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	// Start the Ethernet port. 
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	// Display the port MAC address. 
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	// Enable RX in promiscuous mode for the Ethernet device. 
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(uint16_t port)
{

    printf("Send packets every 250 us\n");
    
    int ret;
    char *eth_hdr;

    struct rte_mbuf *m;

    m = rte_pktmbuf_alloc(mbuf_pool);

    m->nb_segs = 1;
    m->next = NULL;
    m->data_len = (uint16_t)LEN;
    eth_hdr = rte_pktmbuf_append(m,m->data_len);
    rte_memcpy(eth_hdr, buf, LEN);

    uint64_t hz = rte_get_tsc_hz();
    uint64_t ticks_250_us = hz / 4000;

    uint64_t g_NextTicksNs = rte_rdtsc() + (hz * 3); // start after 3 seconds

    while(1)
    {	
        if(unlikely(g_NextTicksNs < rte_rdtsc()))//ensure timing in nanoseconds, and test as much as possible
	{		
	    	ret = rte_eth_tx_burst(port, 0, &m, 1);

		m = rte_pktmbuf_alloc(mbuf_pool);

		m->nb_segs = 1;
		m->next = NULL;
		m->data_len = (uint16_t)LEN;
		eth_hdr = rte_pktmbuf_append(m,m->data_len);
		rte_memcpy(eth_hdr, buf, LEN);

		if(unlikely(ret < 1)) {
			rte_pktmbuf_free(m);
		}
		g_NextTicksNs += ticks_250_us;

                if(g_NextTicksNs < rte_rdtsc())
                {
                    printf("Error: missed deadline\n");
                }
        }
    }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{
	
	unsigned nb_ports = 1;
	uint16_t portid = 0;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	if(argc > 1 )
        {
		int num = -1;
		sscanf (argv[1],"%d",&num);
		if(num >= 0 && num < 0x10000)
		{
			portid = (uint16_t) num;
			printf("\nport %u set\n", portid);
		}
		else
			rte_exit(EXIT_FAILURE, "Error with port config, only numbers between 0 and 65535 allowed\n");
        }
	else
	{
		printf("\ndefault port %u set\n", portid);
	}

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize port. */
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

	/* Call lcore_main on the master core only. */
	if (rte_eth_dev_socket_id(portid) > 0 && rte_eth_dev_socket_id(portid) != (int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to polling thread.\n\tPerformance will not be optimal.\n", portid);


	/* Call lcore_main on the main core only. */
	lcore_main(portid);

	return 0;
}
