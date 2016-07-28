
function Flow_DetectRogueDhcpServer (dpiMsg, ruleEngine)
 -- Trigger an alarm if a non-approved DHCP server shows up on the network
 -- This rule currently has two DHCP server IP addresses setup. Please 
 -- change this to fit your network setup
 
 --This rule is an example of how to use insider knowledge of your network to 
 --create alarms for suspicious behavior.  Dynamic Host Control Protocol (DHCP)
 --is a well-known system for getting a valid IP address on a network.  DHCP is 
 -- also critical for discovering other core services such as DNS servers or 
 -- gateway IP addresses.  Unfortunately, the power of DHCP is very tempting for
 --malicious actors. There are numerous exploits where rogue DHCP services were 
 --started on a corporate network. The rogue service competes with the legitimate
 --service but also gives the attacker a means to pass traffic through proxies, 
 --direct systems to compromised DNS, perform IP spoofing or take many other 
 -- types of disruptive actions.
 --
 --If you know the IP address of your legitimate DHCP servers, you can use this
 -- rule to look for any DHCP activity that is unauthorized.  More often than 
 -- not, you will find developer or test systems that are running DHCP in a 
 -- benign (but unauthorized) fashion.  However, you may also find rogue 
 -- DHCP services that are indicators of compromise and wider ranging exploits.
 
 require 'LOG'
 
  -- convert list to set
   function Set (list)
      local set = {}
      for _, l in ipairs(list) do set[l] = true end
         return set
   end
  
   if (dhcp == nil) then
      dhcp = "dhcp"
      servers = {"10.128.64.242", "10.1.20.20"}
      approvedServers = Set(servers)
   end
   
   local protocol  = GetLatestApplication(dpiMsg)
   if (protocol == dhcp) then
      local dhcpServer = GetString(dpiMsg, dhcp, "siaddr")
      if (dhcpServer ~= nil and dhcpServer ~= "0.0.0.0") then
         if (not approvedServers[dhcpServer]) then
            SetCustomField(dpiMsg, "SIAddr", dhcpServer)
            WARNING(debug.getinfo(1, "S"), "Rogue DHCP server detected. UUID: ",  GetUuid(dpiMsg),  ", SIADDR: ",  dhcpServer)
            TriggerUserAlarm(dpiMsg, ruleEngine, "high")
         end
      end
   end
end