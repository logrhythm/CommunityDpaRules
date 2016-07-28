# Community DPA Rules for Network Monitor
This repository contains community DPA rules for network monitor. These rules are examples which often require custom modifications, such as modifying allowed IP-ranges etc. 

# Contributions: 
The following details are required when adding an example DPA rule

1. /lrl: 
   * the lrl binary file for the rule
2. /pcap:  
    * at least one pcap which would trigger the rule. Additonal pcaps are encouraged as well as pcaps that does not trigger the rule
    * one yaml file per pcap that describes
    ```
    DESCRIPTION:Description of what the rule does and its purpose
    SCOPE: Flow/Packet
    Alarm: Yes/No
    CUSTOM_METADATA: (blank)/MY_CUSTOMFIELD_NM=<what it is>
    ```
3.  /rules:
    * The .lua rule that was used to create the binary
    * one yaml file that describes
    ```
    DESCRIPTION: <describe in a short sentence the rule's mission>
    AUTHOR: <who wrote it>
    SCOPE: Flow/Packet
    ```


# License:
All rules here are bound by the MIT License, copyright LogRhythm


