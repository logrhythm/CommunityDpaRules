# Community DPA Rules for Network Monitor
This repository contains community DPA rules for network monitor. These rules are examples which often require custom modifications, such as modifying allowed IP-ranges etc. 

# Contributions: 
The following details are required when adding an example DPA rule

1. /lrl: 
   * the lrl binary file for the rule
2. /pcap:  
    * at least one pcap which would trigger the rule. Additonal pcaps are encouraged as well as pcaps that does not trigger the rule
    * one readme file that describes
    ```
    PCAP: Flow_NAME_1.pcap (example: DetectRogueDhcpServer_1.pcap) = some description of the expected result when replaying the pcap
    DESCRIPTION:Description of what the rule does and its purpose
    AUTHOR: 
    SCOPE: Flow or Packet
    ```
3.  /rules:
    The .lua rule that was used to create the binary


# License:
All rules here are bound by the MIT License, copyright LogRhythm