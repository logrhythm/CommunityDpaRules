function Flow_ClassifyEncryptedTraffic (msg, ruleEngine)
-- Adds a metadata field if the traffic uses a knwon encryption classification

require 'LOG'

-- list of known crypto protocols
if (cryptoProtocols == nil) then 
     cryptoProtocols = {"ipsec","ssl", "ssh", "sftp", "rdp"}
end
     
 -- if you need to increase efficiency then you can 
 -- put the logic inside a check for 
 -- if (IsFinalLongFlow(msg) or IsFinalShortFlow(msg)) then 
   
-- path string will look something like /tcp/ssl/https
local appPath = GetString(msg, "internal", "applicationpath")
   -- iterate over crypto protocols
    for k,v in pairs(cryptoProtocols) do 
        if (string.find(appPath,v)) then 
            SetCustomField(msg, "EncryptedTraffic", "true")
            SetCustomField(msg, "EncryptedTrafficType", v)            
            return
        end 
    end 
end 