#!/bin/bash
while [ 1 ]
do 
  sudo chown dpi:dpi *.pcap
  cp -f *.pcap /usr/local/probe/upload/.
  sleep 5
done
