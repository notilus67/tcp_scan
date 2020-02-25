#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''
necessary lib: IPy (pip3 install IPy)

usage: connect_scan.py [-h] target [-p <port range>] [-cp <top common ports>] [-ap <all ports]

examples: 
  python3 connect_scan.py https://librarysearch.royalholloway.ac.uk/ 
  (scan top 1000 most used ports by default)
  python3 connect_scan.py 31.186.254.178-31.186.254.179 -p 1443 -cp 20
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
'''

from socket import *
from common import * # common.py: option parsing functions & most used posts
import threading
import argparse
import sys
import time
import datetime

# argparse & help document
parser = argparse.ArgumentParser(description='example: \n  python3 connect_scan.py 31.186.254.178-31.186.254.179 -p 8888 -cp 20', 
                                usage='connect_scan.py [-h] target [-p <port range>] [-cp <top common ports>] [-ap <all ports]', formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('target', help='\
    IP address,       e.g. 192.168.1.2\n\
    IP address range, e.g. 192.168.10.0-192.168.10.255\n\
    CIDR,             e.g. 192.168.0.0/24, 192.168.10.0/255.255.0.0\n\
    domain            e.g. www.royalholloway.ac.uk')
parser.add_argument('-p', '--port', help='port range, e.g. 1-1000,443')
parser.add_argument('-ap', '--all_port', help='port: 1-65535', default=False, action='store_true')
parser.add_argument('-cp', '--common_port', choices=['20', '100', '1000'], help='top most used port numbers [default: 1000]')

args = parser.parse_args()

def port_scan(host, port):
    #print ("scanning %s:%s" % (host,port))
    #for i in range(1,100000): pass
    global openNum
    global scannedNum
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((str(host), port))
        lock.acquire()
        openNum += 1
        scannedNum += 1
        try:
            print('[+] %s:%-5d open   %-6s' %(str(host), port, getservbyport(port, "tcp")))
        except Exception as e1:
            print('[+] %s:%-5d open   %-6s' %(str(host), port, 'unknown'))
        lock.release()
        s.close()
    except Exception as e:
        #print (e)
        scannedNum += 1
        pass

lock = threading.Lock()
openNum = 0
scannedNum = 0
threads = []

if __name__ == '__main__':
    setdefaulttimeout(3)
    hosts = format_host(args.target)  # parse IP-like input or domain name
    ports = format_port(args.port, args.common_port, args.all_port) # parse port-like input
    print ("\n[ %s ] Scan started - Target: %s\n" % (datetime.datetime.now().strftime("%H:%M:%S - %d/%m/%Y"), args.target))
    for host in hosts:
        print ("Scanning %s" % (host))
        for port in ports:
            t = threading.Thread(target=port_scan, args=(host, port))
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
    print ("[ %s ] Scan finished.\n" % (datetime.datetime.now().strftime("%H:%M:%S - %d/%m/%Y"))) 
