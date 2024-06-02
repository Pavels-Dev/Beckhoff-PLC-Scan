local nmap = require('nmap')
local stdnse = require('stdnse')
local shortport = require('shortport')
local http = require("http")

author = "Pavel S - University of Applied Sciences Aachen"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

description = [[
  This Nmap dissector initiates an ADS discovery message to identify Beckhoff 
  Programmable Logic Controllers (PLCs) on the network. Upon detection, it extracts and 
  organizes relevant data from the discovery message for further analysis and insight 
  without disrupting the function of the PLC itself.
]]

---
-- @usage
-- nmap --script twincat-scan.nse -p 48899 <target>
--
-- @output
-- Host script results:
--[[ || Beckhoff Dissector: 
|   Discovery_Analysis: 
|     
|       Hostname: X
|     
|       AMS_NetID: X
|     
|       Operating_System: X
|     
|       Twincat_Version: X
|     
|       Fingerprint: X
|   Devices: 
|     Devices: 
|       CX5020: X%
|       CX9020: X%
|     Details: 
|       SNMP: Enabled
|       NAT-t-IKE: Enabled
|       Webserver: Enabled
|       Telnet: Disabled
|       CE Remote Display: Enabled
|       IPC Diagnostics: Disabled
|       ADS: Enabled
|       SSDP: Enabled
|       ISAKMP: Enabled
|     Best_Match: 
|_      CX9020 with a score of X%
]]--

-- The following two functions are part of Joel Spangs industiral ethernet scanner
-- available at https://www.scada-secure.de/downloads/nmap-scripts/ and have been adopted
-- to to work and imporove the fingerprinting capabilities of this script

local function has_service(host, port, protocol)
	local s = nmap.get_port_state(host, {number = port, protocol = protocol})
	return (s and string.match(s.state, "^open")) or false
end

predict_device = function(host, ads_res)
	
  local ads_res 		= ads_res or false
	local START_SCORE 	= 10
	local details 		= {}
	local weights = {
		["must-have"] = math.huge, ["should-have"] = 2, ["optional"] = 1, ["cant-have"] = 0
	}
	local services 	= {
		-- Beckhoff CX5020 Embedded PC
		["CX5020"] 	= {
			["must-have"] 	= {
				["ADS"] 				= ads_res
			},
			["should-have"] = {
				["Webserver"] 			= has_service(host, 443, 	"tcp"),
				["IPC Diagnostics"] 	= has_service(host, 5120,	"tcp")
			},
			["optional"] 	= {
				["Telnet"] 				= has_service(host, 23,		"tcp"),
				["SNMP"] 				= has_service(host, 161,  	"udp"),
				["CE Remote Display"] 	= has_service(host, 987, 	"udp"),
				["SSDP"] 				= has_service(host, 1900, 	"udp")
			},
      ["cant-have"] 	= {
				["test"] 				= has_service(host, 99999,		"tcp"),
			}
		},
		-- Beckhoff CX9020 Embedded PC
		["CX9020"] 	= {
			["must-have"] 	= {
				["ADS"] 				= ads_res
			},
			["should-have"] = {
				["Webserver"] 			= has_service(host, 443, 	"tcp"),
				["IPC Diagnostics"] 	= has_service(host, 5120,	"tcp"),
				["ISAKMP"] 				= has_service(host, 500,	"udp"),
				["NAT-t-IKE"] 			= has_service(host, 4500,	"udp")
			},
			["optional"] 	= {
				["SNMP"] 				= has_service(host, 161,  	"udp"),
				["SSDP"] 				= has_service(host, 1900, 	"udp")
			},
      ["cant-have"] 	= {
				["test"] 				= has_service(host, 99999,		"tcp"),
			}
		},

	}
	local devices = {
		["CX5020"] = START_SCORE, ["CX9020"] = START_SCORE
	}

	do
		-- Calculate the score for each device we specified
		for deviceName, categories in pairs(services) do
			local score = devices[deviceName]

			-- Run through each category and adjust the score accordingly
			for category, srvcs in pairs(categories) do
				local weight = weights[category]

				for service, enabled in pairs(srvcs) do
					if not enabled then
						score = math.max(0, score - weight)
						details[service] = "Disabled"
					else
						details[service] = "Enabled"
					end
				end
        if category == "cant-have" then
          for service, enabled in pairs(srvcs) do
            if  enabled then
              score = 0
              details[service] = "Disabled"
            else
              details[service] = "Enabled"
            end
          end
        end
      end
      

			devices[deviceName] = score
		end
	end

	-- Finalize scores
	local dev, maxscore = nil, 0
	for device, score in pairs(devices) do
		local calc = (math.max(0, score) / START_SCORE) * 100
		devices[device] = string.format("%4.2f%%", calc)
		
		if calc > maxscore then
			dev = device
			maxscore = calc
		end
	end

	local bestmatch
	if dev == nil then
		bestmatch = {"Device could not be identified!"}
	else
		bestmatch = {string.format("%s with a score of %4.2f%%", dev, maxscore)}
	end
	return devices, details, bestmatch
end

-- A collection of String that define the OS in 
local os_map = {
  {"1401000006000000000000000000000003", "Windows CE 6"},
  {"0600000001000000b11d000002", "Windows CE 7"},
  {"523049393751340004001401140100000a00000000000000654", "Windows 10"},
}

-- A support function that transltes hex values to ASCII
function hexToAscii(hexString)
  return (hexString:gsub('..', function (cc)
    return string.char(tonumber(cc,  16))
  end))
end

--This function send a login attempt to the host with default credentials.
local function try_default(host, socket)
  local login_payload = "\x03\x66\x14\x71\x00\x00\x00\x00\x06\x00\x00\x00\xc0\xa8"..
  "\x00\x06\x01\x01\x10\x27\x05\x00\x00\x00\x0c\x00\x0a\x00\x4e\x4d\x41\x50\x2d".. 
  "\x53\x43\x41\x4e\x00\x07\x00\x06\x00\xc0\xa8\x00\x06\x01\x01\x0f\x00\x10\x00"..
  "\xb3\xce\xfa\x9d\xf1\x4c\xdf\x60\xcc\x32\xdf\xef\x27\xe2\xd7\x91\x0e\x00\x10"..
  "\x00\x3b\x5b\x00\xf2\x6b\x76\x2d\xd1\xad\xd7\xf5\x68\xb7\xe3\x8a\x6f\x05\x00"..
  "\x0c\x00\x31\x39\x32\x2e\x31\x36\x38\x2e\x30\x2e\x37\x00"

  local status, err = socket:sendto(host.ip, 48899, login_payload)
  if not status then
    stdnse.debug1("Failed to send UDP packet: %s", err)
    return nil
  end
  local status, data = socket:receive_bytes(1)
  data = stdnse.tohex(data)
  local len = string.len(data)
  
  if string.sub(data,len-7,len-4) == "0000" then
    return "WARNING DEFAULT CREDENTIALS DETECTED: Administrator/1 \n"..
           "\tYou can extract more precise Information at https://" .. host.ip .. "/config \n"..
           "\tYou may need to reduce your minimum TLS Setting as some Beckhoff devices \n\tare still configured to use TLS 1.0"
  else
    return "Default credentials have been changed. If you have the credentials you can login\n" ..
      "at https://" .. host.ip .. "/config to get the exact Modell of this device"..
      "tYou may need to reduce your minimum TLS Setting as some Beckhoff devices \n\tare still configured to use TLS 1.0"
      
  end
end

--Compares given OS string to already indexed OS string to try to determine the used OS
local function get_os(os)
  for i, os_pair in ipairs(os_map) do
    if string.find(os, os_pair[1]) ~= nil then
      return os_pair[2]
    end
  end
  return "Not listed yet\nIf you are aware of the specific Operating System running on this host," ..
  "we encourage you to contribute that information to this repository."..
  "Your input will enhance the accuracy and effectiveness of this dissector.\n" ..
  "https://github.com/Pavels-Dev/Beckhoff-PLC-Scan" 
end

--Returns the TwinCat Version based on given data
local function get_version(version)
  local major = tonumber(string.sub(version, 5,6),16)
  local minor = tonumber(string.sub(version, 7,8),16)
  local build = tonumber(string.sub(version, 11,12) .. string.sub(version, 9,10),16)
  return "" .. major .. "." .. minor .."." .. build
end

-- Attempts to translate the discovery response by the Device running TwinCat XAR
local function ads_translate(bytes)

  local output = stdnse.output_table()

  local pos = 17

  -- Message type Byte 

  pos = pos + 6

  --Response Byte

  pos = pos + 2

  -- AMS-NetId

  local netid_bytes = string.sub(bytes, pos,pos+11)
  local netid = ""
  for i=0,5 do
      local part = string.sub(netid_bytes, i*2+1,i*2+2)
      netid = netid .. (i>0 and "." or "") .. tonumber(tostring(part), 16)
  end
  
  stdnse.debug1("AMS-NetId: %s", netid)

  pos = pos + 28
  local len_hostname = string.sub(bytes, pos, pos+1)
  len_hostname = tonumber("0x" .. len_hostname)

  pos = 57

  local hostname = string.sub(bytes, pos, pos+len_hostname*2)
  hostname = hexToAscii(hostname)
  stdnse.debug1("hostname: %s", hostname)

  pos = pos + len_hostname
  local version_out = ""
  local os_out = ""
  local fingerprint = "Not used in Twincat Version 2"
  if string.len(bytes)/2 > 380 then --If the message is longer than 380 it probably also has a Fingerprint which is is feature of Twincat3
    local os = string.sub(bytes,pos, string.len(bytes) - 128 - 6)
    local version = ""
    if string.len(bytes) % 2 == 1 then
      version = string.sub(bytes,string.len(bytes) - 128 - 22, string.len(bytes) - 128 -10)
      fingerprint = hexToAscii(string.sub(bytes, -132, -5))
    
    else
      fingerprint = hexToAscii(string.sub(bytes, -130, -4))
      version = string.sub(bytes,string.len(bytes) - 128 - 21, string.len(bytes) - 128 -9)
    end
    version_out = get_version(version)
    os_out = get_os(os)
    stdnse.debug1("Windows: %s", os_out)
    stdnse.debug1("Twincat: %s", version_out)

  else
    local os = string.sub(bytes, pos, string.len(bytes) - 6)
    --stdnse.debug1("Windows String: %s",os)    
    local version = ""
    if string.len(bytes) % 2 == 1 then
      version = string.sub(bytes, string.len(bytes)-12, string.len(bytes))
    else
      version = string.sub(bytes, string.len(bytes)-11, string.len(bytes))
    end
    version_out = get_version(version)
    os_out = get_os(os)
    stdnse.debug1("Windows: %s", os_out)
    stdnse.debug1("Twincat: %s", version_out)

  end
  output.Discovery_Analysis = {
      {Hostname = hostname},
      {AMS_NetID = netid},
      {Operating_System = os_out},
      {Twincat_Version = version_out},
      {Fingerprint = fingerprint}

    
  }
  return output
end

--This script executes when it detects that the default Beckhoff Port is no closed
portrule = shortport.portnumber(48899,"udp",{"open","open|filtered","filtered"})

action = function(host, port)
  --ads_translate("036614710000000001000080c0a800060101102704000000050010004445534b544f502d523049393751340004001401140100000a00000000000000654a00000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030004000301b80f120041006332393935326133393736363333343233663131383931336138346230616336373166383431656235363833376232373039646536363366306339373166393100")
  local target = host.ip
  local udp_payload = "\x03\x66\x14\x71\x00\x00\x00\x00\x01\x00\x00\x00\xc0\xa8\x00\x06\x01\x01\x10\x27\x00\x00\x00\x00" -- Your UDP payload here
  local udp_port = port.number

  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- Timeout in milliseconds

  socket:connect(host, port, "udp")

  local status, err = socket:sendto(target, udp_port, udp_payload)
  if not status then
    stdnse.debug1("Failed to send UDP packet: %s", err)
    return nil
  end

  local status, data = socket:receive_bytes(1)
  local output
  
  if status then
    output = ads_translate(stdnse.tohex(data))
    local devices, details, bestmatch = predict_device(host, true)
    output.Devices = {
      Devices = {
        CX9020 = devices["CX9020"],
        CX5020 = devices["CX5020"]},
      Details = details,
      Best_Match = bestmatch
    }
    if stdnse.get_script_args("default_pw") then
    output.Default_Credentials = {
      try_default(host, socket)
    }
  end
  end
  return output

end

