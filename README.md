# portScanDetector
This code base detects port scans given a .pcap file. C++ is the language used along with CMake packages for PCAP file handling. The scans that can be detected are listed below:

TCP SYN </br>
TCP Connect </br>
Ping </br>
UDP Scan </br>

** make sure your cmake is up to date!

## To build and run:
** navigate to project directory first! 

>~ mkdir build </br>
>~ cd build </br>
>~ cmake .. </br>
>~ make </br>
>~ ./portscanner "absPathToPCAP" </br>

