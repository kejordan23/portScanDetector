/*
 * Author: Kylie Jordan
 * Project: Port Scan Detector
 *
 * This project takes a PCAP file as input and analyzes packet data for specific port scans.
 * Port scan types able to be detected:
 *
 * TCP/SYN
 * Ping
 * TCP Connect
 * UDP
 *
 */
#include <iostream>
#include "Parse.h"

int main(int argc, char **argv) {
    Parse p;
    //input absolute path to file here
    string t = argv[1];
    p.doParse(t);
    p.detScan();
    return 0;
}
