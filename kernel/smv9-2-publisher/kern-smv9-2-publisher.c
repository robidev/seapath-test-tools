/* Copyright (C) 2021, Alliander (http://www.alliander.com)
   SPDX-License-Identifier: Apache-2.0
*/
#define _GNU_SOURCE
#include <sched.h>
#include <sys/types.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h> 
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <time.h>  /* for struct timespec */

#define BUF_SIZE 1500

#ifndef DEBUG_SOCKET
#define DEBUG_SOCKET 0
#endif

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


/* assembly code to read the TSC */
static inline uint64_t RDTSC()
{
  unsigned int hi, lo;
  __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));
  return ((uint64_t)hi << 32) | lo;
}
 
const int NANO_SECONDS_IN_SEC = 1000000000;
/* returns a static buffer of struct timespec with the time difference of ts1 and ts2
   ts1 is assumed to be greater than ts2 */
struct timespec *TimeSpecDiff(struct timespec *ts1, struct timespec *ts2)
{
  static struct timespec ts;
  ts.tv_sec = ts1->tv_sec - ts2->tv_sec;
  ts.tv_nsec = ts1->tv_nsec - ts2->tv_nsec;
  if (ts.tv_nsec < 0) {
    ts.tv_sec--;
    ts.tv_nsec += NANO_SECONDS_IN_SEC;
  }
  return &ts;
}
 
double g_TicksPerNanoSec;

//O3 will optimize out the while loop, causing wrong ticks per second estimate
static void __attribute__((optimize("O0"))) CalibrateTicks()
{
  struct timespec begints, endts;
  uint64_t begin = 0, end = 0;


  clock_gettime(CLOCK_MONOTONIC, &begints);
  begin = RDTSC();

  uint64_t i;
  for (i = 0; i < 1000000; i++); /* must be CPU intensive */

  end = RDTSC();
  clock_gettime(CLOCK_MONOTONIC, &endts);


  struct timespec *tmpts = TimeSpecDiff(&endts, &begints);
  uint64_t nsecElapsed = (tmpts->tv_sec * (uint64_t)1000000000LL) + tmpts->tv_nsec;
  printf("nsecElapsed: %lu, end-begin: %lu\n", nsecElapsed, end - begin);
  g_TicksPerNanoSec = (double)(end - begin)/(double)nsecElapsed;
  printf("g_TicksPerNanoSec: %f\n", g_TicksPerNanoSec);
}
 
/* Call once before using RDTSC, has side effect of binding process to CPU1 */
void InitRdtsc(unsigned long cpuMask)
{

  sched_setaffinity(getpid(), sizeof(cpuMask), (cpu_set_t *)&cpuMask);
  CalibrateTicks();
}
 
void GetTimeSpec(struct timespec *ts, uint64_t nsecs)
{
  ts->tv_sec = nsecs / NANO_SECONDS_IN_SEC;
  ts->tv_nsec = nsecs % NANO_SECONDS_IN_SEC;
}
 
/* ts will be filled with time converted from TSC reading */
void GetRdtscTime(struct timespec *ts)
{
  GetTimeSpec(ts, RDTSC() / g_TicksPerNanoSec);
}







struct sEthernetSocket {
    int rawSocket;
    bool isBind;
    struct sockaddr_ll socketAddress;
};
typedef struct sEthernetSocket* EthernetSocket;

static int getInterfaceIndex(int sock, const char* deviceName)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, deviceName, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        if (DEBUG_SOCKET)
            printf("ETHERNET_LINUX: Failed to get interface index");
        return -1;
    }

    int interfaceIndex = ifr.ifr_ifindex;

    if (ioctl (sock, SIOCGIFFLAGS, &ifr) == -1)
    {
        if (DEBUG_SOCKET)
            printf("ETHERNET_LINUX: Problem getting device flags");
        return -1;
    }

    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1)
    {
        if (DEBUG_SOCKET)
            printf("ETHERNET_LINUX: Setting device to promiscuous mode failed");
        return -1;
    }

    return interfaceIndex;
}

void Ethernet_destroySocket(EthernetSocket ethSocket)
{
    close(ethSocket->rawSocket);
    free(ethSocket);
}

EthernetSocket Ethernet_createSocket(const char* interfaceId, uint8_t* destAddress)
{
    EthernetSocket ethernetSocket = calloc(1, sizeof(struct sEthernetSocket));

    if (ethernetSocket) {
        ethernetSocket->rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

        if (ethernetSocket->rawSocket == -1) {
            if (DEBUG_SOCKET)
                printf("Error creating raw socket!\n");
            free(ethernetSocket);
            return NULL;
        }

        ethernetSocket->socketAddress.sll_family = PF_PACKET;
        ethernetSocket->socketAddress.sll_protocol = htons(ETH_P_IP);

        int ifcIdx =  getInterfaceIndex(ethernetSocket->rawSocket, interfaceId);

        if (ifcIdx == -1) {
            Ethernet_destroySocket(ethernetSocket);
            return NULL;
        }

        ethernetSocket->socketAddress.sll_ifindex = ifcIdx;

        ethernetSocket->socketAddress.sll_hatype =  ARPHRD_ETHER;
        ethernetSocket->socketAddress.sll_pkttype = PACKET_OTHERHOST;

        ethernetSocket->socketAddress.sll_halen = ETH_ALEN;

        memset(ethernetSocket->socketAddress.sll_addr, 0, 8);

        if (destAddress != NULL)
            memcpy(ethernetSocket->socketAddress.sll_addr, destAddress, 6);

        ethernetSocket->isBind = false;
    }

    return ethernetSocket;
}



int main(int argc, char *argv[]) {

    int nread = LEN;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    EthernetSocket sock;
    if((sock = Ethernet_createSocket(argv[1],NULL)) == NULL)
    {
        fprintf(stderr, "Error creating raw socket for interface [%s]\n", argv[1]);
        return 0;
    }
    

    if (sock->isBind == false) {
        if (bind(sock->rawSocket, (struct sockaddr*) &sock->socketAddress, sizeof(sock->socketAddress)) == 0)
        {
            sock->isBind = true;
            fprintf(stdout, "Raw socket bind succesfull\n");
        }
        else
        {
            fprintf(stderr, "Error binding raw socket for interface [%s]\n", argv[1]);
            return 0;
        }
    }
    
    InitRdtsc(4); // bind to cpu 1
    fprintf(stdout, "Send packets every 250 us\n");
    
    struct timespec begints;
    clock_gettime(CLOCK_REALTIME, &begints);
    time_t start = begints.tv_sec + 5;
    
    fprintf(stdout, "wait 5 seconds until start\n");
    do
    {
        clock_gettime(CLOCK_REALTIME, &begints);
    }
    while(begints.tv_sec <= start);//make this on a absolute second bound

    double g_NextTicksNs = RDTSC() + (g_TicksPerNanoSec * (double)1000000000.0); // start after one more second 
    int iter = 0;
    while(1) 
    {	
        if(__builtin_expect(g_NextTicksNs < RDTSC(),0))//ensure timing in nanoseconds, and test as much as possible
	{
		buf[41] = (iter & 0xff00) >> 8;
		buf[42] = iter & 0x00ff;
		iter = (iter + 1) % 4000;
		if (sendto(sock->rawSocket, buf, nread, 0, (struct sockaddr*) &(sock->socketAddress), sizeof(sock->socketAddress)) != nread)
		{
		    fprintf(stderr, "Error sending packet\n");
		}
		g_NextTicksNs += (g_TicksPerNanoSec * (double)(1000.0 * 250.0));//next 250 us
                if(g_NextTicksNs < RDTSC())
                {
                    fprintf(stderr, "Error: missed deadline on iter: %i\n", iter);
		    CalibrateTicks();
		    g_NextTicksNs = RDTSC() + (g_TicksPerNanoSec * (double)1000000000.0); // start after one more second 
                }
	}
    } 

    Ethernet_destroySocket(sock);
    return 0;
} 
