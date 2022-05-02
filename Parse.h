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
#include <pcap.h>
#include "Packet.h"
#include <vector>

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
private:
    vector<Packet> packets;
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

            int srcport = ntohs(tcp->th_sport);
            int dstport = ntohs(tcp->th_dport);
            //printf("src port: %d dest port: %d \n", srcport, dstport);

            string protocol;
            char srcname[100];
            strcpy(srcname, inet_ntoa(ip->ip_src));
            char dstname[100];
            strcpy(dstname, inet_ntoa(ip->ip_dst));
            //printf("src address: %s dest address: %s \n", srcname, dstname);
            string temp = dstname;

            if(temp == "255.255.255.255")
                protocol = "UDP";
            else
                protocol = "TCP";
            //cout<<"protocol: "<<protocol<<endl;

            u_long seq = ntohl(tcp->th_seq);
            u_long ack = ntohl(tcp->th_ack);
            //printf("seq number: %u ack number: %u \n", seq, ack);
            ++packetCount;
            //printf("Packet # %i\n", ++packetCount);
            //printf("Packet size: %d bytes\n", header->len);

            if (header->len != header->caplen)
                printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);

            Packet p(srcport, dstport, srcname, dstname, protocol, seq, ack, header->len, packetCount);
            packets.push_back(p);

            //printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);

        }
    };
    void detScan(){
        detPingScan();
        detTCPSYNScan();

    };

    void detUDPScan(){

    };

    void detTCPSYNScan(){
        vector<int> scanIps;
        string prevSrc;
        string prevDst;
        int synCnt = 0;
        int prevsynCnt = 0;
        for(int i = 0; i< packets.size(); i++){
            if((packets[i].getSrcIp() == prevDst) && (packets[i].getDstIp() == prevSrc) && packets[i].getProtocol() == "TCP"){
                synCnt++;
            }
            else if(synCnt < 1 && (packets[i].getSrcIp() != prevDst) && (packets[i].getDstIp() != prevSrc) && packets[i-1].getProtocol() == "TCP"){
                scanIps.push_back(i-1);
                synCnt = 0;
            }
            else if(synCnt < 2 && (packets[i].getSrcIp() != prevDst) && (packets[i].getDstIp() != prevSrc) && packets[i-1].getProtocol() == "TCP"){
                scanIps.push_back(i-2);
                synCnt = 0;
            }
            if(synCnt >=2)
                synCnt = 0;
            prevSrc = packets[i].getSrcIp();
            prevDst = packets[i].getDstIp();
        }
        if(scanIps.size() > 0){
            cout<<"TCP/SYN Scan detected!!"<<endl;
            for(int i = 0; i< scanIps.size(); i++) {
                cout << "SrcIp: "<<packets[scanIps[i]].getSrcIp()<<endl;
                cout << "DstIp: "<<packets[scanIps[i]].getDstIp()<<endl;
            }
            cout<<endl;
        }
    };

    void detTCPConnectScan(){

    };

    void detPingScan(){
        vector<int> pingIps;
        vector<int> numPack;
        string prevSrc;
        string prevDst;
        int pingCnt = 0;
        int prevCnt = 0;
        int ran1 = 100;
        int ran2 = 0;
        for(int i = 0; i< packets.size(); i++){
            if((packets[i].getSrcIp() == prevSrc) && (packets[i].getDstIp() == prevDst && packets[i].getProtocol() == "TCP")){
                pingCnt++;
                prevCnt = pingCnt;
                if(ran1 > i)
                    ran1 = i-1;
            }
            else if(prevCnt > 2 && pingCnt == 0) {
                pingIps.push_back(ran1);
                numPack.push_back(prevCnt);
                prevCnt = 0;
            }
            else {
                pingCnt = 0;
                ran1 = 100;
            }
            prevSrc = packets[i].getSrcIp();
            prevDst = packets[i].getDstIp();
        }
        if(pingIps.size() > 0){
            cout<<"Ping Scan detected!!"<<endl;
            for(int i = 0; i< pingIps.size(); i++) {
                cout << "SrcIp: "<<packets[pingIps[i]].getSrcIp();
                cout<< " Num Ips Scanned: "<<numPack[i]<<endl;
            }
            cout<<endl;
        }
    };

    void print(){
        for(int i = 0; i< packets.size(); i++){
            packets[i].print();
        }
    };
};

#endif //PORTDET_PARSE_H
