#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // Check if it's an IP packet (0x0800)
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

        printf("\n============================================\n");
        printf("[+] Captured Packet Details\n");
        printf("============================================\n");
        
        // Ethernet Header
        printf("[Ethernet Header]\n");
        printf("   Source MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("   Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        // IP Header
        printf("[IP Header]\n");
        printf("   Source IP:       %s\n", inet_ntoa(ip->iph_sourceip));   
        printf("   Destination IP:  %s\n", inet_ntoa(ip->iph_destip));    
        printf("   Header Length:   %d bytes\n", ip->iph_ihl * 4);

        // Protocol determination
        printf("[Transport Protocol]\n");
        switch(ip->iph_protocol) {                                 
            case IPPROTO_TCP:
                printf("   Protocol: TCP\n");
                break;
            case IPPROTO_UDP:
                printf("   Protocol: UDP\n");
                break;
            case IPPROTO_ICMP:
                printf("   Protocol: ICMP\n");
                break;
            default:
                printf("   Protocol: other (%d)\n", ip->iph_protocol);
                break;
        }
        printf("============================================\n");
    }
}

char *get_default_interface(char *errbuf) {
    pcap_if_t *alldevs, *d;
    char *dev_name = NULL;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return NULL;
    for (d = alldevs; d != NULL; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK) && d->addresses != NULL) {
            dev_name = strdup(d->name);
            break;
        }
    }
    if (dev_name == NULL && alldevs != NULL) dev_name = strdup(alldevs->name);
    pcap_freealldevs(alldevs);
    return dev_name;
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip"; // Capture all IP traffic
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
    char *device = NULL;

    if (argc >= 2) {
        device = argv[1];
    } else {
        device = get_default_interface(errbuf);
        if (device == NULL) {
            fprintf(stderr, "[-] Error finding default interface: %s\n", errbuf);
            return 1;
        }
    }

    printf("[*] Opening device %s for improved sniffing...\n", device);
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] Could not open device %s: %s\n", device, errbuf);
        if (argc < 2) free(device);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "[-] Could not compile filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        if (argc < 2) free(device);
        return 3;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        fprintf(stderr, "[-] Error setting filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        if (argc < 2) free(device);
        return 4;
    }

    printf("[*] Sniffing IP packets... Press Ctrl+C to stop.\n");
    pcap_loop(handle, 3, got_packet, NULL); // capture 3 packets for testing

    pcap_freecode(&fp);
    pcap_close(handle);
    if (argc < 2) free(device);
    return 0;
}
