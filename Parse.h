/*
 * Author: Kylie Jordan
 *
 * PCAP code modified from: https://stackoverflow.com/questions/21222369/getting-ip-address-of-a-packet-in-pcap-file
 *
 * This is a basic parsing scheme for a pcap file
 */

#ifndef PORTDET_PARSE_H
#define PORTDET_PARSE_H

#include <iostream>
#include <iostream>
#include <pcap.h>

using namespace std;

#define SIZE_ETHERNET 14

struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst; /* source and dest address */
};

struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    u_int32_t th_seq;       /* sequence number */
    u_int32_t th_ack;       /* acknowledgement number */
};

class Parse{
public:
    Parse(){};
    void doParse(string& file){
        char buff[256];

        pcap_t * pcap = pcap_open_offline(file.c_str(), buff);

        struct pcap_pkthdr *header;

        const u_char *data;

        const struct sniff_ip *ip; /* The IP header */
        const struct sniff_tcp *tcp; /* The TCP header */

        u_int packetCount = 0;
        while(int returnVal = pcap_next_ex(pcap, &header, &data) >= 0){
            ip = (struct sniff_ip*)(data + SIZE_ETHERNET);
            tcp = (struct sniff_tcp*)(data + SIZE_ETHERNET + header->len * 4);

            u_short srcport = ntohs(tcp->th_sport);
            u_short dstport = ntohs(tcp->th_dport);
            printf("src port: %d dest port: %d \n", srcport, dstport);

            char srcname[100];
            strcpy(srcname, inet_ntoa(ip->ip_src));
            char dstname[100];
            strcpy(dstname, inet_ntoa(ip->ip_dst));
            printf("src address: %s dest address: %s \n", srcname, dstname);

            u_long seq = ntohl(tcp->th_seq);
            u_long ack = ntohl(tcp->th_ack);
            printf("seq number: %u ack number: %u \n", seq, ack);
            printf("Packet # %i\n", ++packetCount);
            printf("Packet size: %d bytes\n", header->len);

            if (header->len != header->caplen)
                printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);

            printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);

            printf("\n\n");
        }
    };
};

#endif //PORTDET_PARSE_H
