function Flow_DetectWebcamByVendorMAC (dpiMessage, ruleEngine)
   -- Using this rule, Network Monitor can detect and alarm on the listed
   -- internet enabled webcam devices by examining the MAC Address. 
   -- The first three octets of a MAC address are defined according to IEEE 
   -- standards and must be registered by the equipment manufacturer. A total 
   -- of seven of the most common internet camera vendors are included in this script
   --

   require 'LOG'
 
   if (TARGET_VENDOR_MAC_PREFIX == nil) then
      -- List of Vendors MAC Address prefix we want to target
      -- Note: Must be UPPER CASE for matching. More faster.
      TARGET_VENDOR_MAC_PREFIX = {}
      TARGET_VENDOR_MAC_PREFIX["30:8C:FB"] = true -- Dropcam aka. Nest Cam
      TARGET_VENDOR_MAC_PREFIX["00:24:E4"] = true -- Withings
      TARGET_VENDOR_MAC_PREFIX["00:18:03"] = true -- ArcSoft SimpliCam
      TARGET_VENDOR_MAC_PREFIX["BC:51:FE"] = true -- Swann
      TARGET_VENDOR_MAC_PREFIX["8C:AE:89"] = true -- Y-Cam
      TARGET_VENDOR_MAC_PREFIX["00:1F:54"] = true -- Lorex
      
      TARGET_VENDOR_NAME = {}
      TARGET_VENDOR_NAME["30:8C:FB"] = "Dropcam/Nest Cam"
      TARGET_VENDOR_NAME["00:24:E4"] = "Withings"
      TARGET_VENDOR_NAME["00:18:03"] = "ArcSoft SimpliCam"
      TARGET_VENDOR_NAME["BC:51:FE"] = "Swann"
      TARGET_VENDOR_NAME["8C:AE:89"] = "Y-Cam"
      TARGET_VENDOR_NAME["00:1F:54"] = "Lorex"
   end
   
   
   local function GetWebCamVendor(dpiMessage)
      -- Extract Vendor from Src MAC Address
      local srcMAC_Vendor = string.upper(string.sub( GetSrcMacString(dpiMessage), 1, 8))
      if (srcMac_Vendor ~= nil and TARGET_VENDOR_MAC_PREFIX[srcMAC_Vendor]) then
         return srcMac_Vendor, TARGE_VENDOR_NAME[srcMac_Vendor]
      end
   
      -- Extract Vendor from Dst MAC Address
      local dstMAC_Vendor = string.upper(string.sub( GetDstMacString(dpiMessage), 1, 8))  -- Check against our table
      if (dstMac_Vendor ~= nil and TARGET_VENDOR_MAC_PREFIX[dstMAC_Vendor]) then
         return dstMac_Vendor, TARGE_VENDOR_NAME[dstMac_Vendor]
      end
   end
 
   local macAddress, vendorName = GetWebCamVendor(dpiMessage)
   if (vendorName ~=nil) then
      SetCustomField(dpiMessage, "WEBCAM_NAME", vendorName)
      SetCustomField(dpiMessage, "WEBCAM_MAC", macAddress)
      TriggerUserAlarm(dpiMessage, ruleEngine, "low")
      WARNING(debug.getinfo(1, "S"), "Internet enabled webcam detected, UUID: ",  GetUuid(dpiMessage),  ", vendor: ", vendorName, ", mac: ",  macAddress)
   end
end
