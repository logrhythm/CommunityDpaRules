function UnwrapGREHTTP (dpiMsg, packet)
 -- rule content
    require 'LOG'
    require 'HexString'
    
    if packet ~= nil and HasApplication(dpiMsg, 'http') then
        if gGreWrappedIP == nil then
            gGreWrappedIP = {}
        end
        
        local srcIP = StringToHex(GetPacketString(packet, 50, 53))
        
        local sOct1 = tonumber(string.sub(srcIP, 1, 2), 16)
        local sOct2 = tonumber(string.sub(srcIP, 3, 4), 16)
        local sOct3 = tonumber(string.sub(srcIP, 5, 6), 16)
        local sOct4 = tonumber(string.sub(srcIP, 7, 8), 16)
        
        if sOct1 and sOct2 and sOct3 and sOct4 then
            local dstIP = StringToHex(GetPacketString(packet, 54, 57))
            
            local dOct1 = tonumber(string.sub(dstIP, 1, 2), 16)
            local dOct2 = tonumber(string.sub(dstIP, 3, 4), 16)
            local dOct3 = tonumber(string.sub(dstIP, 5, 6), 16)
            local dOct4 = tonumber(string.sub(dstIP, 7, 8), 16)
        
            if dOct1 and dOct2 and dOct3 and dOct4 then
                local sip = sOct1 .. '.' .. sOct2 .. '.' .. sOct3 .. '.' .. sOct4
                local dip = dOct1 .. '.' .. dOct2 .. '.' .. dOct3 .. '.' .. dOct4
                --EZINFO('Src: ', sip, ', Dst: ', dip)
                --SetCustomField(dpiMsg, "SrcIP", sip);
                --SetCustomField(dpiMsg, "DstIP", dip);
                local flowUUID = GetUuid(dpiMsg)
                if gGreWrappedIP[flowUUID] == nil then
                    gGreWrappedIP[flowUUID] = true
                    SetCustomField(dpiMsg, "SrcIP", sip)
                    SetCustomField(dpiMsg, "DstIP", dip)
                end
            end
        end
    
        if EndOfFlow(packet) and gGreWrappedIP[flowUUID] ~= nil then
            gGreWrappedIP[flowUUID] = nil
        end
   end
 
end
