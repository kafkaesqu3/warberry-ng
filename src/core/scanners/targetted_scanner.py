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

import os, os.path
import nmap
from src.utils.console_colors import *
from src.utils.port_obj_Read import port_obj_reader
from pdb import set_trace as bp
import subprocess

class targettedScanner:

    def __init__(self):

        # dict of scanners
        # key = name of service
        # value = Scanner object for that service
        self.scanners={}
        self.results_dir = ""

    def single_port_scanner(self,CIDR, intensity, iface, hostlist, results_dir):
        self.results_dir = results_dir
        print(" ")
        print(bcolors.OKGREEN + " [ PORT SCANNER MODULE ]\n" + bcolors.ENDC)
        print("\n[*] Beginning Scanning Subnet %s" % CIDR)
        print(" ")


        # port_obj_reader reads portlist_config file and creates a list with port_objects for scalability.
        # port list input filename is as below.
        ports_list = port_obj_reader("portlist_config")
        #ports_list = str(ports_list).translate(None, '\'\"][ ')
        #ports_list = ports_list.split(',')

        ports = []
        hosts = []

        #name = str(temp[0])
        #port = str(temp[5]).split('.')
        ##message = str(temp[4])
        #scantype = str(temp[1])


        nmap = "/usr/bin/nmap"
        nmap_args = " -Pn --open " + intensity
        nmap_args += " -e " + iface


        #nmap_host_arg = ""
        for h in hostlist:
            nmap_args += " " + h 

        for service in ports_list:
            service_name = service.getattr("name")
            print("Scanning for %s\n" % service_name)
            nmap_port_arg = ""
            nmap_out_arg = ""
            nmap_type_arg = ""
            scantype = service.getattr("type")
            if (scantype == "y"):
                nmap_type_arg = " -sU -p"
            elif (scantype == "n"):
                nmap_type_arg = " -sS -p"

            port_nums = service.getattr("port")
            for p in port_nums: 
                nmap_port_arg += p + ","
            outfile_name = "%snmap_%s" % (results_dir, service_name)
            nmap_out_arg = " -oA %s" % outfile_name
            
            print 
            
            subprocess.call("%s %s %s %s %s >/dev/null 2>&1" % (nmap, nmap_out_arg, nmap_args, nmap_type_arg, nmap_port_arg), shell=True)