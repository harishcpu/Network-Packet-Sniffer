# Network-Packet-Sniffer
A network packet sniffer built with the help of 'scapy' module which is entirely dedicated to capturing, handling and analyzing network traffic. User has the flexibility to enter the interface to capture the traffic from, the number of packets to sniff, the time interval to the sniffer to be running(time interval to capture the packets in). The application will log the traffic information it captures in a text file and hence user enters the name of the file. The 'packet_log' function filters the packets based on the protocol that user has chosen and saves the packets of that protocol in the log file. This data stored in the file will have every detail of the traffic that is flowing through the interface.

Logical Flow Diagram:

![Logical Flow Diagram](https://user-images.githubusercontent.com/46072258/117496610-e829b480-af94-11eb-9f22-354b9a9773c2.jpg)

Application Execution:
![Running The Application1](https://user-images.githubusercontent.com/46072258/117494874-8b2cff00-af92-11eb-8676-4d402b14d397.PNG)

Generating ARP and ICMP Traffic:
![Generating ICMP and ARP packets](https://user-images.githubusercontent.com/46072258/117494901-9a13b180-af92-11eb-860e-ef44c803b06f.PNG)
