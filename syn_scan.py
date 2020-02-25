#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''
necessary lib: IPy (pip3 install IPy) & scapy (pip3 install scapy)

usage: syn_scan.py [-h] target [-p <port range>] [-cp <top common ports>] [-ap <all ports]

examples: (sudo if Linux)
  python3 syn_scan.py https://librarysearch.royalholloway.ac.uk/ 
  (scan top 1000 most used ports by default)
  python3 syn_scan.py 31.186.254.178-31.186.254.179 -p 1443 -cp 20
  python3 syn_scan.py https://librarysearch.royalholloway.ac.uk/ -cp 100
  python3 syn_scan.py 192.168.0.0/24 -p 443
  python3 syn_scan.py www.royalholloway.ac.uk -ap
  
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
'''

from socket import *
from common import * # common.py: optsocketion parsing functions & most used posts
import threading
import argparse
import sys
import time
import datetime
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# argparse & help document
parser = argparse.ArgumentParser(description='example: \n  python3 syn_scan.py 31.186.254.178-31.186.254.179 -p 8888 -cp 20', 
                                usage='syn_scan.py [-h] target [-p <port range>] [-cp <top common ports>] [-ap <all ports]', formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('target', help='\
    IP address,       e.g. 192.168.1.2\n\
    IP address range, e.g. 192.168.10.0-192.168.10.255\n\
    CIDR,             e.g. 192.168.0.0/24, 192.168.10.0/255.255.0.0\n\
    domain            e.g. www.royalholloway.ac.uk')
parser.add_argument('-p', '--port', help='port range, e.g. 1-1000,443')
parser.add_argument('-ap', '--all_port', help='port: 1-65535', default=False, action='store_true')
parser.add_argument('-cp', '--common_port', choices=['20', '100', '1000'], help='top most used port numbers [default: 1000]')

args = parser.parse_args()

lock = threading.Lock()
openNum = 0
scannedNum = 0
threads = []

def syn_scan(hostname,port):
    global openNum
    global scannedNum
    syn=IP(dst=hostname)/TCP(dport=int(port),flags=2)
    result_raw=sr(syn,timeout=1,verbose=False)
    # gain result_raw into a list
    result_list=result_raw[0].res
    for i in range(len(result_list)):
        # check if 'TCP' exists in the i-th reply packet
        if(result_list[i][1].haslayer(TCP)):
            # gain TCP header
            TCP_Fields=result_list[i][1].getlayer(TCP).fields
            # check if flags = 18 (syn+ack)
            if TCP_Fields['flags']==18:
                port = TCP_Fields['sport']
                try:
                    print('[+] %s:%-5d open   %-6s' %(str(host), port, getservbyport(port, "tcp")))
                except Exception as e1:
                    print('[+] %s:%-5d open   %-6s' %(str(host), port, 'unknown'))
                openNum += 1
    scannedNum += 1

if __name__ == '__main__':
    setdefaulttimeout(3)
    hosts = format_host(args.target)
    ports = format_port(args.port, args.common_port, args.all_port)
    print ("\n[ %s ] Scan started - Target: %s\n" % (datetime.now().strftime("%H:%M:%S - %d/%m/%Y"), args.target))
    source_ip = '192.168.1.2'
    for host in hosts:
        print ("Scanning %s" % (host))
        for port in ports:
            t = threading.Thread(target=syn_scan, args=(str(host), port))
            threads.append(t)
            t.start()
        # wait for all sub-threads to end
        for t in threads:
            t.join()
        for t in threads:
            t.join()
        for t in threads:
            t.join()
        print('[*] %d scanned. A total of %d open port(s).\n' % (scannedNum, openNum))
        openNum = 0
        scannedNum = 0
    print ("[ %s ] Scan finished.\n" % (datetime.now().strftime("%H:%M:%S - %d/%m/%Y"))) 
