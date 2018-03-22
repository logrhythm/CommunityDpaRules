function Flow_DetectLargeICMP (dpiMsg, ruleEngine)
   -- Alarm if ICMP traffic contains abnormally large packets, 
   -- indicative of ICMP tunneling traffic
    
require 'LOG'
   local app = GetLatestApplication(dpiMsg)
   -- Covers icmp and icmp6 traffic
   if (app == "icmp" or app == "icmp6") then
      local size = GetLong(dpiMsg, 'internal', 'totalbytes')
      local numPackets = GetLong(dpiMsg, 'internal', 'totalpackets')
      if (numPackets) then
         local avgPktSize  = size / numPackets
         if avgPktSize >  160 then
            SetCustomField(dpiMsg, "ICMP_PacketSize", avgPktSize)
            WARNING(debug.getinfo(1, "S"), "Possible ICMP tunneling traffic detected. UUID: ",  GetUuid(dpiMsg),  ", Average packet size: ",  avgPktSize)
            TriggerUserAlarm(dpiMsg, ruleEngine, 'high')
           end
        end
   end
end   
