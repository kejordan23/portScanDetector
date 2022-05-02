//
// Created by Kylie Jordan on 5/1/22.
//

#ifndef PORTSCANNER_PACKET_H
#define PORTSCANNER_PACKET_H

#include <iostream>
#include <pcap.h>
#include <string>

using namespace std;

class Packet{
private:
    int srcport = 0;
    int dstport = 0;
    string srcIp;
    string dstIp;
    string protocol;
    u_long seqNum = 0;
    u_long ackNum = 0;
    int size = 0;
    int num = 0;
public:
    Packet(){};
    Packet(int s1, int d1, string s2, string d2, string p, int seq, int ack, int si, int n) : srcport(s1), dstport(d1), srcIp(s2), dstIp(d2), protocol(p), seqNum(seq), ackNum(ack), size(si), num(n){};
    int getSrcPort(){ return srcport;};
    int getDstPort(){ return dstport;};
    string getSrcIp(){ return srcIp;};
    string getDstIp(){ return dstIp;};
    string getProtocol(){ return protocol;};
    int getSeqNum(){ return seqNum;};
    int getAckNum(){ return ackNum;};
    int getSize(){ return size;};
    int getNum(){ return num;};
    void print(){
        cout<<"Packet #: "<<num<<endl;
        cout<<"SrcIp: "<<srcIp<<endl;
        cout<<"DstIp: "<<dstIp<<endl;
        cout<<"SrcPort: "<<srcport<<endl;
        cout<<"DstPort: "<<dstport<<endl;
        cout<<"SeqNum: "<<seqNum<<endl;
        cout<<"AckNum: "<<ackNum<<endl;
        cout<<"Size: "<<size<<endl;
        cout<<endl;
    }
};

#endif //PORTSCANNER_PACKET_H
