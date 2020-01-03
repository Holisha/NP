#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <map>
#include <stdlib.h>
// #define LIMITS 100
// #define SIZE_ETHERNET 14
#define MAC_ADDRSTRLEN 2*6+5+1
// #define ETHER_ADDR_LEN  6
using namespace std;
char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDRSTRLEN];

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}//end mac_ntoa
char *ip_ttoa(u_int8_t flag) {
    static int f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
#define TOS_MAX (sizeof(f)/sizeof(f[0]))
    static char str[TOS_MAX + 1]; //return buffer
    u_int8_t mask = 1 << 7; //mask
    int i;

    for(i = 0 ; i < TOS_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;

    return str;
}//end ip_ttoa

char *ip_ftoa(u_int16_t flag) {
    static int f[] = {'R', 'D', 'M'}; //flag
#define IP_FLG_MAX (sizeof(f)/sizeof(f[0]))
    static char str[IP_FLG_MAX + 1]; //return buffer
    u_int16_t mask = 1 << 15; //mask
    int i;

    for(i = 0 ; i < IP_FLG_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;

    return str;
}//end ip_ftoa
void dump_tcp(u_int32_t length, const u_char *content) {
	struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

	u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
	printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
}
void dump_udp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);

    printf("Protocol: UDP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Length:            %5u| Checksum:          %5u|\n", len, checksum);
    printf("+-------------------------+-------------------------+\n");
}//end dump_udp
int main(int argc, char *argv[]){
	int limit;
	string filename;
	if(argc!=3){
		cerr<<"command error"<<endl;
		return 1;
	}else{
		if(strcmp(argv[1],"-r")==0){
			filename = string(argv[2]);
		}
	}
	// if(argc == 3) limit = atoi(argv[2]);
	// else limit = LIMITS;
	map<string,int> srcIP,dstIP;
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t *handler;
	char *dev;
	// open file
	handler = pcap_open_offline(filename.c_str(),errbuff);

	struct pcap_pkthdr *header;
	const u_char *packet;

	int packetCount = 0;
	struct ether_header *eth_header;
	const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;
	char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
	//tcp info
    const struct sniff_ethernet ethernet; / The ethernet header */
    const struct sniff_ip ip; / The IP header */
    const struct sniff_tcp tcp; / The TCP header */
	u_int size_ip;
    u_int size_tcp;
	time_t tmp;
	struct tm ts;
	char dateBuf[80];
	int res;
	while ((res = pcap_next_ex(handler,&header,&packet))>=0){
		if(res == 0) continue;
		char dst_mac_addr[MAC_ADDRSTRLEN] = {};
    	char src_mac_addr[MAC_ADDRSTRLEN] = {};
		u_int16_t type;
		printf("Packet #%d:\n",++packetCount);
		// formate time
		tmp = header->ts.tv_sec;
		ts = *localtime(&tmp);
		strftime(dateBuf, sizeof(dateBuf), "%a %Y-%m-%d %H:%M:%S", &ts);
		// print info
		printf("Time %s\n", dateBuf);
		printf("Length: %d bytes\n", header->len);
    	printf("Capture length: %d bytes\n", header->caplen);
		eth_header = (struct ether_header *) packet;

		strncpy(dst_mac_addr, mac_ntoa(eth_header->ether_dhost), sizeof(dst_mac_addr));
		strncpy(src_mac_addr, mac_ntoa(eth_header->ether_shost), sizeof(src_mac_addr));
		type = ntohs(eth_header->ether_type);
		printf("+-------------------------+-------------------------+-------------------------+\n");
		printf("| Destination MAC Address:                                   %17s|\n", dst_mac_addr);
		printf("+-------------------------+-------------------------+-------------------------+\n");
		printf("| Source MAC Address:                                        %17s|\n", src_mac_addr);
		printf("+-------------------------+-------------------------+-------------------------+\n");
		if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
			ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
			inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
			u_int version = ipHeader->ip_v;
			u_int header_len = ipHeader->ip_hl << 2;
			u_char tos = ipHeader->ip_tos;
			u_int16_t total_len = ntohs(ipHeader->ip_len);
			u_int16_t id = ntohs(ipHeader->ip_id);
			u_int16_t offset = ntohs(ipHeader->ip_off);
			u_char ttl = ipHeader->ip_ttl;
			u_char protocol = ipHeader->ip_p;
			u_int16_t checksum = ntohs(ipHeader->ip_sum);
        	printf("Protocol: IP\n");
			printf("+-----+------+------------+-------------------------+\n");
			printf("| IV:%1u| HL:%2u| T: %8s| Total Length: %10u|\n",
				version, header_len, ip_ttoa(tos), total_len);
			printf("+-----+------+------------+-------+-----------------+\n");
			printf("| Identifier:        %5u| FF:%3s| FO:        %5u|\n",
				id, ip_ftoa(offset), offset & IP_OFFMASK);
			printf("+------------+------------+-------+-----------------+\n");
			printf("| TTL:    %3u| Pro:    %3u| Header Checksum:   %5u|\n",ttl, protocol, checksum);
			printf("+------------+------------+-------------------------+\n");
			printf("| Source IP Address:                 %15s|\n", sourceIP);
			printf("+---------------------------------------------------+\n");
			printf("| Destination IP Address:            %15s|\n", destIP);
			printf("+---------------------------------------------------+\n");

			// record source IP and destination IP
			srcIP[string(sourceIP)]++;
			dstIP[string(destIP)]++;
			// handle UDP and TCP
			switch (protocol) {
				case IPPROTO_UDP:
					dump_udp(header->caplen, packet);
					break;

				case IPPROTO_TCP:
					dump_tcp(header->caplen, packet);
					break;
			}
		} else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
			printf("ARP\n");
		} else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
			printf("Reverse ARP\n");
		}else{
			printf("not support\n");
		}


		// if(packetCount>=limit) break;
		
	}
	int cntSource,cntDst;
	cntSource = cntDst = 0;
	map<string, int>::iterator iter;
	cout<<"---------------Source IP record---------------"<<endl;;
	for(iter = srcIP.begin(); iter != srcIP.end(); iter++){
		cntSource+=iter->second;
        cout<<iter->first<<" :"<<iter->second<<" times"<<endl;
	}
	cout<<"The count of source IP: "<<cntSource<<endl;
	cout<<"------------Destination IP record-------------"<<endl;;
	for(iter = srcIP.begin(); iter != srcIP.end(); iter++){
        cout<<iter->first<<" :"<<iter->second<<" times"<<endl;
		cntDst+=iter->second;
	}	
	cout<<"The count of destination IP: "<<cntDst<<endl;

	return 0;
}