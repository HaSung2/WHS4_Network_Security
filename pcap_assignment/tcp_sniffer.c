#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

/* Packet handler callback function */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 1. Ethernet Header parsing
    struct ethheader *eth = (struct ethheader *)packet;
    
    // 0x0800 in network byte order is 0x0008 (swap bytes). ntohs converts it to host order (0x0800).
    if (ntohs(eth->ether_type) != 0x0800) {
        return; // Not an IPv4 packet, ignore
    }
    
    // 2. IP Header parsing
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    
    // Verify protocol is TCP
    if (ip->iph_protocol != IPPROTO_TCP) {
        return; // Not a TCP packet, ignore
    }
    
    // IP header length is dynamic, specified in 32-bit (4-byte) words
    int ip_header_len = ip->iph_ihl * 4;
    if (ip_header_len < 20) {
        return; // Invalid IP header length
    }
    
    // 3. TCP Header parsing
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    
    // TCP header length (Data Offset) is dynamic, specified in 32-bit (4-byte) words
    int tcp_header_len = TH_OFF(tcp) * 4;
    if (tcp_header_len < 20) {
        return; // Invalid TCP header length
    }
    
    static int packet_count = 1;
    printf("======================================================================\n");
    printf("[+] Packet #%d Captured\n", packet_count++);
    printf("======================================================================\n");
    
    // Print Ethernet Information
    printf("[Ethernet Header]\n");
    printf("   Source MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("   Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
           
    // Print IP Information
    printf("[IP Header]\n");
    printf("   Source IP:       %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Destination IP:  %s\n", inet_ntoa(ip->iph_destip));
    printf("   IP Header Len:   %d bytes\n", ip_header_len);
    printf("   Total Packet Len:%d bytes\n", ntohs(ip->iph_len));
    
    // Print TCP Information
    printf("[TCP Header]\n");
    printf("   Source Port:     %d\n", ntohs(tcp->tcp_sport));
    printf("   Destination Port:%d\n", ntohs(tcp->tcp_dport));
    printf("   TCP Header Len:  %d bytes\n", tcp_header_len);
    
    // 4. Application Layer Payload (HTTP Message)
    int total_headers_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    
    // Payload length = Total IP length - IP header length - TCP header length
    int tcp_payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
    
    printf("[HTTP Message / Application Data]\n");
    if (tcp_payload_len > 0 && total_headers_len <= header->caplen) {
        const u_char *payload = packet + total_headers_len;
        printf("   Payload Size:    %d bytes\n", tcp_payload_len);
        printf("----------------------------------------------------------------------\n");
        
        // Print printable characters (safe print to prevent terminal escape sequences)
        int bytes_to_print = tcp_payload_len;
        if (bytes_to_print > 1024) {
            bytes_to_print = 1024; // Limit output size to prevent flooding
        }
        
        for (int i = 0; i < bytes_to_print; i++) {
            char c = payload[i];
            if (isprint((unsigned char)c) || c == '\n' || c == '\r' || c == '\t') {
                putchar(c);
            } else {
                putchar('.'); // Mask unprintable binary character
            }
        }
        
        if (tcp_payload_len > 1024) {
            printf("\n... [Truncated: showing first 1024 of %d bytes] ...\n", tcp_payload_len);
        }
        printf("\n----------------------------------------------------------------------\n");
    } else {
        printf("   No Application Data (TCP control packet or empty payload)\n");
    }
    printf("\n");
}

/* Helper function to automatically discover an active network interface */
char *get_default_interface(char *errbuf) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char *dev_name = NULL;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return NULL;
    }
    
    // Find the first interface that is not a loopback and has addresses associated with it
    for (d = alldevs; d != NULL; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK) && d->addresses != NULL) {
            dev_name = strdup(d->name);
            break;
        }
    }
    
    // Fallback to loopback if no external interface was found
    if (dev_name == NULL && alldevs != NULL) {
        dev_name = strdup(alldevs->name);
    }
    
    pcap_freealldevs(alldevs);
    return dev_name;
}

int main(int argc, char *argv[]) {
    char *device = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // Filter string to capture only TCP traffic
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;

    // Determine the device to capture on
    if (argc >= 2) {
        device = argv[1];
        printf("[*] Using specified interface: %s\n", device);
    } else {
        device = get_default_interface(errbuf);
        if (device == NULL) {
            fprintf(stderr, "[-] Error finding default interface: %s\n", errbuf);
            return 1;
        }
        printf("[*] Automatically selected interface: %s\n", device);
    }

    // Open the device for live capture
    // Parameters: device, snapshot length, promiscuous mode (1), timeout in ms, error buffer
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] Could not open device %s: %s\n", device, errbuf);
        if (argc < 2) free(device);
        return 2;
    }

    // Compile filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "[-] Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        if (argc < 2) free(device);
        return 3;
    }

    // Set compile BPF filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[-] Could not set filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        if (argc < 2) free(device);
        return 4;
    }

    printf("[*] Successfully started sniffing TCP packets on %s...\n", device);
    printf("[*] Press Ctrl+C to stop.\n\n");

    // Start sniffing loop (runs until error or interrupted)
    pcap_loop(handle, -1, got_packet, NULL);

    // Clean up
    pcap_freecode(&fp);
    pcap_close(handle);
    if (argc < 2) free(device);
    
    return 0;
}
