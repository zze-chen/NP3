#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <pcap.h>
#define OFFMASK 0x1fff
#define MAX_IP 100
#define FILE_LEN 20
#define MAC_ADDLEN 18
typedef struct{
    int num;
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
}Counter;
int pair_cnt = 0;
Counter counter[MAX_IP];

char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDLEN];
    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    return str;
}

char *ip_ttoa(u_int8_t flag) {
    static int f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
    #define TOS_MAX (sizeof(f)/sizeof(f[0]))
    static char str[TOS_MAX + 1];
    u_int8_t mask = 1 << 7;
    int i;
    for(i = 0 ; i < TOS_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }
    str[i] = 0;
    return str;
}

char *ip_ftoa(u_int16_t flag) {
    static int f[] = {'R', 'D', 'M'};
    #define IP_FLG_MAX (sizeof(f)/sizeof(f[0]))
    static char str[IP_FLG_MAX + 1];
    u_int16_t mask = 1 << 15;
    int i;
    for(i = 0 ; i < IP_FLG_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }
    str[i] = 0;
    return str;
}

void dump_tcp(u_int32_t length, const u_char *content) {
	struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    // determine endianness
	u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    //printf("----------------------------------------------------\n");
	printf("Protocol: TCP\n");
    printf("Source Port:       %5u\t Destination Port:  %5u\n", source_port, destination_port);
    printf("----------------------------------------------------\n");
}

void dump_udp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    // determine endianness
    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);
    //printf("----------------------------------------------------\n");
    printf("Protocol: UDP\n");
    printf("Source Port:       %5u\tDestination Port:  %5u\n", source_port, destination_port);
    printf("Length:            %5u\tChecksum:          %5u\n", len, checksum);
    printf("----------------------------------------------------\n");
}

int main(int argc, char **argv){
    int i,cnt=0;
    char *file_name;
    if(argc != 3){
        printf("Error input type\n");
    }else if(strcmp(argv[1] ,"-r") == 0){
        file_name = strdup(argv[2]);
    }
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handler = pcap_open_offline(file_name, errbuff);
    char *dev;
    struct pcap_pkthdr *header;
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    char src_ip[INET_ADDRSTRLEN];   
    char dst_ip[INET_ADDRSTRLEN];  
    for(i = 0; i < MAX_IP; i++){
        counter[i].num = 0;
        memset(counter[i].srcIP, '\0', INET_ADDRSTRLEN);
        memset(counter[i].dstIP, '\0', INET_ADDRSTRLEN);
    }
    u_char *packet;
    int packet_cnt = 0;
    u_int size_ip;
    u_int size_tcp;
    time_t tmp;
    struct tm ts;
	char dateBuf[80];
	int res;
    u_int version, header_len;
    u_char tos, ttl, protocol;
    u_int16_t total_len, id, offset, checksum;
    while((res = pcap_next_ex(handler, &header, &packet)) >= 0){
        if(res == 0) continue;
        char dst_mac_addr[MAC_ADDLEN] = {};
    	char src_mac_addr[MAC_ADDLEN] = {};
		u_int16_t type;
		printf("Packet number:%d\n",++packet_cnt);

		tmp = header->ts.tv_sec;
		ts = *localtime(&tmp);
		strftime(dateBuf, sizeof(dateBuf), "%a %Y-%m-%d %H:%M:%S", &ts);

		printf("Time %s\n", dateBuf);
		printf("Length: %d bytes\n", header->len);
    	printf("Capture length: %d bytes\n", header->caplen);
		eth_header = (struct ether_header *) packet;

		strncpy(dst_mac_addr, mac_ntoa(eth_header->ether_dhost), sizeof(dst_mac_addr));
		strncpy(src_mac_addr, mac_ntoa(eth_header->ether_shost), sizeof(src_mac_addr));

		printf("Destination MAC Address:                                   %17s\n", dst_mac_addr);
		printf("Source MAC Address:                                        %17s\n", src_mac_addr);

		if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
			ip_header = (struct ip*)(packet + sizeof(struct ether_header));
			inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
			tos = ip_header->ip_tos;
			offset = ntohs(ip_header->ip_off);
            //printf("----------------------------------------------------\n");
        	printf("Protocol: IP\n");
			printf("IV:%1u\t HL:%2u\t T: %8s\t Total Length: %10u\n", ip_header->ip_v, ip_header->ip_hl << 2, ip_ttoa(tos), ntohs(ip_header->ip_len));
			printf("Identifier:        %5u\t FF:%3s\t FO:        %5u\n", ntohs(ip_header->ip_id), ip_ftoa(offset), offset & OFFMASK);
			printf("TTL:    %3u\tPro:    %3u\t Header Checksum:   %5u\n",ip_header->ip_ttl, ip_header->ip_p, ntohs(ip_header->ip_sum));
			printf("Source IP Address:                 %15s\n", src_ip);
			printf("Destination IP Address:            %15s\n", dst_ip);
            printf("----------------------------------------------------\n");
			// handle UDP and TCP
			switch (protocol) {
				case IPPROTO_UDP:
					dump_udp(header->caplen, packet);
					break;

				case IPPROTO_TCP:
					dump_tcp(header->caplen, packet);
					break;
			}
		}
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
			printf("ARP\n");
            printf("----------------------------------------------------\n");
		}
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_REVARP){
			printf("Reverse ARP\n");
            printf("----------------------------------------------------\n");
		}
		else{
			printf("NOPE\n");
		}
	}
    return 0;
}