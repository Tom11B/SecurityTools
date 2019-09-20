# Host Scan 

This tool scans a list of host addresses with virus total, this list can be created using Wireshark or any network capture software you choose, the default name of the file is set to addresses.txt but it can be changed in the source code to accept a user supplied name. The code is written to catch the rate limit error and wait the required time before continuing. Compiled using visual studio with the VirusTotal.NET API library.  
