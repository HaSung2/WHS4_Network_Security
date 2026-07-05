#ifdef __linux__
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>

int main() {
    int PACKET_LEN = 512;
    char buffer[PACKET_LEN];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);
    struct packet_mreq mr;

    // Create the raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
    if (sock < 0) {
        perror("ERROR creating raw socket");
        return 1;
    }

    // Turn on the promiscuous mode.
    memset(&mr, 0, sizeof(mr));
    mr.mr_type = PACKET_MR_PROMISC;  
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        perror("ERROR setting promiscuous mode");
        close(sock);
        return 1;
    }

    printf("[*] Raw Socket Sniffer started (Linux)... Press Ctrl+C to stop.\n");

    // Capture a few packets for testing and then exit
    int count = 0;
    while (count < 5) {
        int data_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr, &saddr_len);
        if (data_size > 0) {
            printf("[+] Got packet #%d (size: %d bytes)\n", ++count, data_size);
        }
    }

    close(sock);
    return 0;
}
#else
#include <stdio.h>
int main() {
    printf("[-] sniff_raw.c is designed for Linux systems using AF_PACKET.\n");
    printf("[-] On macOS, please use the PCAP API version (sniff.c) instead.\n");
    return 0;
}
#endif
