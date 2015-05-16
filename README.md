# IR_stuff
Repo for random IR scripts I come up with


###netxml2pcap###
After running ```netsh trace start capture=yes tracefile=test.trace persistent=no maxsize=10MB && timeout 20 && netsh trace stop && netsh trace convert input=test.trace output=foo.xml dump=xml``` you can run ```python netxml2pcap.py foo.xml output.pcap``` and it will convert it to pcap.
References:
https://isc.sans.edu/diary/No+Wireshark%3F+No+TCPDump%3F+No+Problem!/19409

