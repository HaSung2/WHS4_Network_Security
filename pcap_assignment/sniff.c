#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 0;
    printf("[+] Got a packet #%d (size: %d bytes)\n", ++count, header->len);
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
    char filter_exp[] = "icmp";
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

    printf("[*] Opening device %s for sniffing ICMP...\n", device);
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

    printf("[*] Sniffing ICMP packets... Press Ctrl+C to stop.\n");
    
    // We capture up to 3 packets or loop until error
    pcap_loop(handle, 3, got_packet, NULL);                    

    pcap_freecode(&fp);
    pcap_close(handle);
    if (argc < 2) free(device);
    return 0;
}
