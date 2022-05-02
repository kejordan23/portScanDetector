# portscanner
This project involves the implementation of a portscan detector. A port scanner is a program that automatically detects security weaknesses in a remote or localhost. When hackers attack a site, they often try each port in turn to see which are available and not blocked by a firewall or TCP wrapper. This scan can be recognized by a series of packets from one host to another in a short period of time. Port scans are aimed at many different ports, often in an increasing or decreasing sequence.

** make sure your cmake is up to date!

# To build and run:
** navigate to project directory first! 

>> mkdir build
>> cd build
>> cmake ..
>> make
>> ./portscanner <absPathToPCAP>

WARNING: No IPv4 address found on ap1 !
WARNING: No IPv4 address found on awdl0 !
WARNING: more No IPv4 address found on llw0 !


Xmas scan not detected

UDP scan not detected

NULL scan not detected

Half scan not detected

ICMP scan detected. Number of packets : 8

ICMP packet. Source: 192.168.0.114 Destination: 192.168.0.1

ICMP packet. Source: 192.168.0.114 Destination: 192.168.0.1

ICMP packet. Source: 192.168.0.114 Destination: 192.168.0.1

ICMP packet. Source: 192.168.0.114 Destination: 192.168.0.1

ICMP packet. Source: 192.168.0.114 Destination: 72.14.207.99

ICMP packet. Source: 192.168.0.114 Destination: 72.14.207.99

ICMP packet. Source: 192.168.0.114 Destination: 72.14.207.99

ICMP packet. Source: 192.168.0.114 Destination: 72.14.207.99
