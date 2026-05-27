#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

struct libnet_ethernet_hdr {
    unsigned char  ether_dhost[6];
    unsigned char  ether_shost[6];
    unsigned short ether_type;
};

struct libnet_ipv4_hdr {
    unsigned char  ip_v_hl;
    unsigned char  _pad1[8];
    unsigned char  ip_p;
    unsigned char  _pad2[2];
    unsigned char  ip_src[4];
    unsigned char  ip_dst[4];
};

struct libnet_tcp_hdr {
    unsigned short th_sport;
    unsigned short th_dport;
    unsigned char  _pad1[8];
    unsigned char  th_x2_off;
};

unsigned short my_ntohs(unsigned short n) {
    return ((n & 0xFF00) >> 8) | ((n & 0x00FF) << 8);
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;
        if (my_ntohs(eth->ether_type) != 0x0800) continue;

        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + 14);
        if (ip->ip_p != 6) continue;

        int ip_len = (ip->ip_v_hl & 0x0F) * 4;
        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)((unsigned char*)ip + ip_len);

        int tcp_len = ((tcp->th_x2_off & 0xF0) >> 4) * 4;
        const unsigned char* payload = (const unsigned char*)tcp + tcp_len;
        int payload_len = header->caplen - (14 + ip_len + tcp_len);

        printf("==========Ethernet Header==========\n");
        printf("Dst Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
        printf("Src Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

        printf("==========IP Header==========\n");
        printf("Src IP : %d.%d.%d.%d\n", ip->ip_src[0], ip->ip_src[1], ip->ip_src[2], ip->ip_src[3]);
        printf("Dst IP : %d.%d.%d.%d\n", ip->ip_dst[0], ip->ip_dst[1], ip->ip_dst[2], ip->ip_dst[3]);

        printf("==========TCP Header==========\n");
        printf("Src Port : %d\n", my_ntohs(tcp->th_sport));
        printf("Dst Port : %d\n", my_ntohs(tcp->th_dport));

        int print_len = (payload_len > 20) ? 20 : payload_len;
        if (print_len <= 0) {
            printf("No Data\n\n");
        } else {
            for (int i = 0; i < print_len; i++) {
                printf("%02x ", payload[i]);
            }
            printf("\n\n");
        }
    }

    pcap_close(pcap);
    return 0;
}
