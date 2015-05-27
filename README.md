# IR_stuff
Repo for random IR scripts I come up with


###netxml2pcap###
After running:
 
```netsh trace start capture=yes tracefile=test.trace persistent=no maxsize=10MB && timeout 20 && netsh trace stop && netsh trace convert input=test.trace output=trace.xml dump=xml``` 

You can run:
 
```python netxml2pcap.py trace.xml output.pcap``` 

and then you will have a pcap in the current directory. Basically it reads out the packet data from the xml and adds the pcap header and writes it to a file. Note that the get_packet_data() generator returns a time, packet data, and the processid sending the traffic.


References:
https://isc.sans.edu/diary/No+Wireshark%3F+No+TCPDump%3F+No+Problem!/19409



###Invoke-RawCap.ps1###

This is a script I wrote to capture localhost traffic, i.e. like RawCap.exe but in powershell. Tested in powershell v2 on Win7.
