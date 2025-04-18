"""
This file is part of the WarBerry tool.
Copyright (c) 2018 Yiannis Ioannides (@sec_groundzero).
https://github.com/secgroundzero/warberry
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""

import os
from src.utils.utils import *
import nmap

class static:

    def __init__(self):
        valid_IPS_Discovered=[]
        subnets=[]

    def static_bypass(self,ifname):

        print("      [ STATIC IP SETUP MODULE ]\n")

        print("ARP Scanning Network for IPs\n")
        #subprocess.call("sudo netdiscover -i %s -P -l ./src/discover | grep -P -o \'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*? ' | grep -P -o \'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' > ../Results/ips_discovered" %ifname, shell = True)
	nm=nmap.PortScanner()
	nm_arp=nm.scan(hosts="192.168.10.0/24",arguments="-sP")
	print "Demo!!!"
	for x in s.items()[1][1]:
		print x 
        if os.stat('Results/ips_discovered').st_size !=0:
            discover = open("Results/ips_discovered","r")
            ips = discover.readlines()
            print("Testing validity of %s IP(s)captured" % (sum(1 for _ in discover)))
            discover.close()

            for ip in ips:
                if not ip_validate(ip):
                    print("[+] %s is valid" %ip.strip())
                    self.valid_IPS_Discovered.append(ip)
                else:
                    print("[-] %s is invalid" %ip.strip())

            self.valid_IPS_Discovered.sort()

            return (create_subnet(ifname))
        else:
            print("[-] No IPs captured! Exiting")
            return


    def create_subnet(self,ifname):
        subs = self.valid_IPS_Discovered
        subnets=[]
        for sub in subs:
            subnets.append('.'.join(sub.split('.')[0:-1]) + '.')

        subset = set(subnets)
        self.subnets = list(subset)

    def set_static(self,ifname):

        print ("\nARP Scanning based on targetted CIDR\n")
        subprocess.call(
                "sudo netdiscover -i %s -P -l ./src/discover | grep -P -o \'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*? ' | grep -P -o \'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' > Results/used_ips" % ifname,
                shell=True)

        subs=self.subnets
        avail=[]
        statics=[]

        for sub in subs:
            for i in range(1, 255):
                avail.append(sub.strip() + str(i))

        with open('Results/used_ips', 'r') as used:
            used_ips = used.readlines()
            for available in avail:
                isUsed = False
                for used in used_ips:
                    if ((available.strip() == used.strip()) and (isUsed == False)):
                        print("[-] IP %s is in use, excluding from static list" % used.strip())
                        isUsed = True
                    if (isUsed == False):
                        statics.append(available)

            with open('Results/statics') as static:
                total_frees = sum(1 for _ in static)
                if total_frees > 0:
                    print
                    '\n%s Available IPs to choose from.' % total_frees
                else:
                    print
                    "No free IPs Found\n"

            with open('Results/statics', 'r') as statics:
                line_count = (sum(1 for _ in statics))
                for i in range(0, line_count):
                    newline = randint(0, line_count)

                    static = linecache.getline('Results/statics', newline)
                    print
                    "[*] Attempting to set random static ip %s" % static.strip()
                    subprocess.call(["ifconfig", ifname, static.strip(), "netmask", netmask.strip()])

                    for used in reversed(open('Results/used_ips').readlines()):
                        print
                        "[*] Pinging %s to ensure that we are live..." % used.strip()
                        ping_response = subprocess.call(['ping', '-c', '5', '-W', '3', used.strip()],
                                                        stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
                        if ping_response == 0:
                            print
                            "[+] Success. IP %s is valid and %s is reachable" % (
                            static.strip(), used.strip())
                            return static.strip()
                        else:
                            print
                            "[-] Failed. IP %s is not valid" % static.strip()
                    print
                    "Attempting to bypass MAC Filtering\n"
                    return (macbypass(CIDR, ifname))
