/* Copyright (C) 2021, Alliander (http://www.alliander.com)
   SPDX-License-Identifier: Apache-2.0
*/
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

#define BUF_SIZE 1500

#ifndef DEBUG_SOCKET
#define DEBUG_SOCKET 0
#endif

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
	//set ethertype
        ethernetSocket->socketAddress.sll_protocol = htons(ETH_P_ALL);
    }

    return ethernetSocket;
}



int main(int argc, char *argv[]) {

    uint8_t buffer[BUF_SIZE];
    int bufferSize = BUF_SIZE;
    int nread = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    //uint8_t mac[6] = {0x01,0x0c,0xcd,0x01,0x00,0x03};
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

    fprintf(stdout, "Read ethernet packets and echo them back to sender\n");
    for (;;) {
        
        nread = recvfrom(sock->rawSocket, buffer, bufferSize, MSG_DONTWAIT, 0, 0);
	//ignore mac address of invalid packets
        if (nread == -1 || buffer[6] == 0x01 && buffer[7] == 0x02 && buffer[8] == 0x03 && buffer[9] == 0x04 && buffer[10] == 0x05 && buffer[11] == 0x06)
        {
            continue;               /* Ignore failed request */
        }
	//fprintf(stdout, "m: %d\n",buffer[6]);
       
        if (sendto(sock->rawSocket, buffer, nread, 0, (struct sockaddr*) &(sock->socketAddress), sizeof(sock->socketAddress)) != nread)
        {
            fprintf(stderr, "Error sending response\n");
        }
    } 

    Ethernet_destroySocket(sock);
    return 0;
} 
