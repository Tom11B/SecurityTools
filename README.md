# Host Scan 

This tool scans a list of host addresses with virus total, the list can be created using Wireshark or any network capture software you choose. The default name of the file is set to addresses.txt but it can be changed in the source code to accept a user supplied input. The code is written to catch the rate limit error and wait the required time before continuing. Compiled using visual studio 2019 with the VirusTotal.NET API library.  

The output provides a link for later follow-up and results can be saved for reporting. Happy Hunting!

![Alt text](https://github.com/Tom11B/SecurityTools/blob/master/VirusTotal_Program.PNG?raw=true "Tool Output")
