# Beckhoff-PLC-Scan
This Nmap dissector is designed to identify Beckhoff Programmable Logic Controllers (PLCs) and extract comprehensive information about them.
## Instalation
Download the .nse file Nmap scripts should be placed in the Nmap scripts directory. The location of this directory varies depending on your operating system:
Windows: Typically, the scripts folder is located at C:\Program Files (x86)\Nmap\scripts\.
Linux and macOS: Usually, it's located at /usr/local/share/nmap/scripts/ or /usr/share/nmap/scripts/, depending on how Nmap was installed.
## Usage
To use the script you need to scan for the UDP-port 48899
If you want to use the port based model detection you'll need to scan for these aditional ports TCP: 23, 102, 443, 4500, 5120, 8000, UDP: 161m 500, 987, 1900, 4500, 48899
```bash
sudo nmap 192.168.0.4 --script twincat-scan.nse -p U:161,500,4500,987,1900,48899,T:23,102,443,4500,5120,8080 -sSU
```
## Example Output
PORT     STATE SERVICE
48899/udp open|filtered unknown
| Beckhoff Dissector: 
|   Discovery_Analysis: 
|     
|       Hostname: BBECK9023
|     
|       AMS_NetID: 5.15.101.188.1.1
|     
|       Operating_System: Windows CE 6
|     
|       Twincat_Version: 3.1.4024
|     
|       Fingerprint: dd2326d2306dda4338c0205f14e27159ed9191ad603a7a5e827efc468a1f6076
|   Devices: 
|     Devices: 
|       CX5020: 70.00%
|       CX9020: 80.00%
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
|_      CX9020 with a score of 80.00%
MAC Address: 00:01:05:0F:65:BC (Beckhoff Automation GmbH)

## Disclaimer:

This tool is designed for information technology security purposes only. It should be used exclusively on networks and systems where explicit authorization has been obtained. Unauthorized scanning of networks and systems is illegal and unethical. Users must ensure they have written permission from the rightful owners of the systems to be scanned. We are not responsible for any misuse of this tool, nor for any consequences that result from such misuse. It is the user's responsibility to adhere to all applicable laws and regulations related to network scanning and data security. Use this tool at your own risk.
## Tested on
CX-5020
CX-9020
