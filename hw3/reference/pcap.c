#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
 
/* record that the packet from which source to which destination */
struct record
{
    int packet_num;
    int flag;
    char source[20];
    char destnation[20];
};
struct record packet_record[20];

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 4096
 
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
 
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
 
/* Ethernet header */
 struct sniff_ethernet
 {
  u_char ether_dhost[ETHER_ADDR_LEN];	/* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN];	/* source host address */
  u_short ether_type;		/* IP? ARP? RARP? etc */
 };
 
/* IP header */
 struct sniff_ip
 {
  u_char ip_vhl;		/* version << 4 | header length >> 2 */
  u_char ip_tos;		/* type of service */
  u_short ip_len;		/* total length */
  u_short ip_id;		/* identification */
  u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  u_char ip_ttl;		/* time to live */
  u_char ip_p;			/* protocol */
  u_short ip_sum;		/* checksum */
  struct in_addr ip_src, ip_dst;	/* source and dest address */
 };
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
 
/* TCP header */
 typedef u_int tcp_seq;
 
/* UDP header */
 struct sniff_udp
 {
  uint16_t sport;		/* source port */
  uint16_t dport;		/* destination port */
  uint16_t udp_length;
  uint16_t udp_sum;		/* checksum */
};
 
struct sniff_tcp
{
  u_short th_sport;		/* source port */
  u_short th_dport;		/* destination port */
  tcp_seq th_seq;		/* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */
  u_char th_offx2;		/* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;		/* window */
  u_short th_sum;		/* checksum */
  u_short th_urp;		/* urgent pointer */
};
 
void got_packet (u_char * args, const struct pcap_pkthdr *header,const u_char * packet);
 
void print_payload (const u_char * payload, int len);
 
void print_hex_ascii_line (const u_char * payload, int len, int offset);
 
 
/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line (const u_char * payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;
 
    /* offset */
    printf ("%05d   ", offset);
 
    /* hex */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        printf ("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
        printf (" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf (" ");
 
    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf ("   ");
        }
    }
    printf ("   ");
 
    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (isprint (*ch))
            printf ("%c", *ch);
        else
            printf (".");
        ch++;
    }
    printf ("\n");
    return;
}
 
/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload (const u_char * payload, int len)
{ 
    int len_rem = len;
    int line_width = 16;		/* number of bytes per line */
    int line_len;
    int offset = 0;		/* zero-based offset counter */
    const u_char *ch = payload;
 
    if (len <= 0)
        return;
 
    /* data fits on one line */
    if (len <= line_width)
    {
        print_hex_ascii_line (ch, len, offset);
        return;
    }
 
    /* data spans multiple lines */
    for (;;)
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line (ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
	        /* print last line and get out */
            print_hex_ascii_line (ch, len_rem, offset);
            break;
        }
    }
 
    return;
}
 
/*
 * dissect/print packet
 */
void got_packet (u_char * args, const struct pcap_pkthdr *header,const u_char * packet)
{   
    static int count = 1;		/* packet counter */
    unsigned char *mac_string;	// MAC address
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;	/* The ethernet header [1] */
    const struct sniff_ip *ip;	/* The IP header */
    const struct sniff_tcp *tcp;	/* The TCP header */
    const struct sniff_udp *udp;	/* The UDP header */
    const char *payload;		/* Packet payload */
 
    int size_ip;
    int size_tcp;
    int size_payload;
    
    printf("----------------------------------------------------\n");
	printf("%s\n", ctime((time_t *)&(header->ts.tv_sec))); //time
    printf ("Packet number %d:\n", count);
    count++;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet *) (packet);
    
    //get MAC source address
    mac_string = (unsigned char *)ethernet->ether_shost;
    // print MAC source address
    printf("Mac Source Address:  %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),\
    *(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    
    //get MAC destination address
	mac_string = (unsigned char *)ethernet->ether_dhost;
    // print MAC source address
	printf("Mac Destination Address:  %02x:%02x:%02x:%02x:%02x:%02x\n", *(mac_string+0),\
    *(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip) * 4;
    if (size_ip < 20)
    {
        printf ("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
 
    /* print source and destination IP addresses */
    if(ip->ip_p==IPPROTO_IP || ip->ip_p==IPPROTO_TCP || ip->ip_p==IPPROTO_UDP || ip->ip_p==89)
    {
        printf ("\nSource: %s  ->  Destination: %s\n", inet_ntoa (ip->ip_src) , inet_ntoa (ip->ip_dst));
        char ip_src_addr[20] , ip_dst_addr[20];
        int i,j;
        strcpy(ip_src_addr,inet_ntoa (ip->ip_src));
        strcpy(ip_dst_addr,inet_ntoa(ip->ip_dst));
        /* count the number of packet from source to destination*/
        for(i=0;i<20;i++)
        {
            if(strcmp(packet_record[i].source,ip_src_addr)==0 && strcmp(packet_record[i].destnation,ip_dst_addr)==0)
            {
                packet_record[i].packet_num = packet_record[i].packet_num + 1;
                break;
            }
            else if(packet_record[i].flag==0)
            {
                strcpy(packet_record[i].source , ip_src_addr);
                strcpy(packet_record[i].destnation , ip_dst_addr);
                packet_record[i].flag = 1;
                packet_record[i].packet_num = packet_record[i].packet_num + 1;
                break;
            }
        }
    }

    /* determine protocol */
    switch (ip->ip_p)
    {
        case IPPROTO_TCP:
            printf ("-----Protocol: TCP-----\n");
            break;
        case IPPROTO_UDP:
            printf ("-----Protocol: UDP-----\n");
            break;
        case IPPROTO_ICMP:
            printf ("-----Protocol: ICMP-----\n");
            return;
        case IPPROTO_IP:
            printf ("-----Protocol: IP-----\n");
            return;
        default:
            printf ("-----Protocol: unknown-----\n");
        return;
    }
 
    /* This packet is TCP. */
    if (ip->ip_p == IPPROTO_TCP)
    {
      /* define/compute tcp header offset */
        tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF (tcp) * 4;
        if (size_tcp < 20)
        {
            printf ("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return;
        }
 
        printf ("   Src port: %d\n", ntohs (tcp->th_sport));
        printf ("   Dst port: %d\n\n", ntohs (tcp->th_dport));
        printf("----------------------------------------------------\n");

        /* define/compute tcp payload (segment) offset */
        payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
 
        /* compute tcp payload (segment) size */
        size_payload = ntohs (ip->ip_len) - (size_ip + size_tcp);
 
        /* Print payload data; it might be binary, so don't just treat it as a string. */
       if (size_payload > 0)
       {
            printf ("   Payload (%d bytes):\n", size_payload);
            print_payload (payload, size_payload);
       }
    }//end tcp
 
    /* This packet is UDP */
    else if (ip->ip_p == IPPROTO_UDP)
    {
        /* define/compute udp header offset */
        udp = (struct sniff_udp *) (packet + SIZE_ETHERNET + size_ip);
        printf ("   Src port: %d\n", ntohs (udp->sport));
        printf ("   Dst port: %d\n\n", ntohs (udp->dport));
        //printf ("udp length:%d\n", ntohs (udp->udp_length));
        //printf ("udp sum:%d\n\n", ntohs (udp->udp_sum));
        printf("----------------------------------------------------\n");
        /* define/compute udp payload (segment) offset */
        payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + 8);
        size_payload = ntohs (ip->ip_len) - (size_ip + 8);
 
        /*  Print payload data; it might be binary, so don't just treat it as a string. */
        if (size_payload > 0)
        {
            printf ("   Payload (%d bytes):\n", size_payload);
            print_payload (payload, size_payload);
        }
    }//end udp
 
    return;
}
 
int main (int argc, char **argv)
{
    char *dev = NULL;		/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
    pcap_t *handle;		/* packet capture handle */
 
    char filter_exp[] = "ip";	/* filter expression [3] */
    struct bpf_program fp;	/* compiled filter program (expression) */
    bpf_u_int32 mask;		/* subnet mask */
    bpf_u_int32 net;		/* ip */
    int num_packets = -1;		//number of packets to capture
    int i,j;

    /* initial */
    for(i=0;i<20;i++)
    {
        packet_record[i].packet_num = 0;
        packet_record[i].flag = 0;
        for(j=0;j<20;j++)
        {
            packet_record[i].source[j] = '\0';
            packet_record[i].destnation[j] = '\0';
        }
    }

    /* check for capture device name on command-line */
    if (argc == 3)
    {
        dev = argv[2];
        handle = pcap_open_offline(dev,errbuf);
    }
    else
    {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev (errbuf);
        if (dev == NULL)
        {
            fprintf (stderr, "Couldn't find default device: %s\n", errbuf);
            exit (EXIT_FAILURE);
        }
        if (pcap_lookupnet (dev, &net, &mask, errbuf) == -1)
        {
            fprintf (stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
            net = 0;
            mask = 0;
        }
        handle = pcap_open_live (dev, SNAP_LEN, 1, 0, errbuf);
        if (handle == NULL)
        {
            fprintf (stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit (EXIT_FAILURE);
        }
    }
 
    /* get network number and mask associated with capture device */
    /*if (pcap_lookupnet (dev, &net, &mask, errbuf) == -1)
    {
        fprintf (stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
        net = 0;
        mask = 0;
    }*/
 
    /* print capture info */
    printf ("Device: %s\n", dev);
    //printf ("Number of packets: %d\n", num_packets);
    printf ("Filter expression: %s\n", filter_exp);
 
    /* open capture device */
    /*handle = pcap_open_live (dev, SNAP_LEN, 1, 0, errbuf);
    if (handle == NULL)
    {
        fprintf (stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit (EXIT_FAILURE);
    }*/

    /* compile the filter expression */
    /*
    if (pcap_compile (handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf (stderr, "Couldn't parse filter %s: %s\n",
        filter_exp, pcap_geterr (handle));
        exit (EXIT_FAILURE);
    }*/

    /* apply the compiled filter */
    /*
    if (pcap_setfilter (handle, &fp) == -1)
    {
        fprintf (stderr, "Couldn't install filter %s: %s\n",
        filter_exp, pcap_geterr (handle));
        exit (EXIT_FAILURE);
    }
    */
 
    /* now we can set our callback function */
    pcap_loop (handle, num_packets, got_packet, NULL);
 
    /* cleanup */
    //pcap_freecode (&fp);
    pcap_close (handle);
 
    for(i=0;i<20;i++)
    {
        if(packet_record[i].flag==1)
        {
            printf("Packet_num = %d.  From %s to %s\n",packet_record[i].packet_num,packet_record[i].source,packet_record[i].destnation);
        }
    }
    printf ("\nCapture complete.\n");
 
  return 0;
}