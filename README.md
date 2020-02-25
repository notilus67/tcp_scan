# tcp_scan
tcp connect / syn scan, for coursework only

# requirements
Python 3
IPy
scapy

# usage
```
usage: connect_scan.py [-h] target [-p <port range>] [-cp <top common ports>] [-ap]

examples:
  python3 connect_scan.py https://librarysearch.royalholloway.ac.uk/ 
  (scan top 1000 most used ports if no options)
  python3 connect_scan.py 31.186.254.178-31.186.254.179 -p 1443 -cp 20
  (scan port 1443 + top 20 most used ports)
  python3 connect_scan.py https://librarysearch.royalholloway.ac.uk/ -cp 100
  python3 connect_scan.py 192.168.0.0/24 -p 443
  python3 connect_scan.py www.royalholloway.ac.uk -ap
  
positional arguments:
  target                    IP address,       e.g. 192.168.1.2
                            IP address range, e.g. 192.168.10.0-192.168.10.255
                            CIDR,             e.g. 192.168.0.0/24, 192.168.10.0/255.255.0.0
                            domain            e.g. www.royalholloway.ac.uk

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  port range, e.g. 1-1000,443
  -ap, --all_port       port: 1-65535
  -cp {20,100,1000}, --common_port {20,100,1000}
                        top most used port numbers [default: 1000]
```
