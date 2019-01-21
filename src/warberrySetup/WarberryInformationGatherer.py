from src.core.enumeration.ip_enum import *
from src.core.enumeration.network_packets import *
from src.core.scanners.targetted_scanner import *
from src.core.enumeration.services_enum import *
from src.utils.utils import *
import nmap
import os

# I want to refactor this so you give it a target subnet and it goes and does the recon
# Warberry.py should call this module against its local LAN, and then if enabled, we should call this against another network

# this will require refactoring out everything related to localhost networking configuration
class WarberryInformationGatherer:

    IPsFound=""

    def __init__(self, CIDR, timestamp):
        self.CIDR=CIDR
        self.liveIPs=[]
        self.scanners={}
        self.enumeration={}
        self.timestamp = timestamp
        self.cidr_dir = CIDR.replace('/', '-')
        self.directory_name = "Results/%s_%s/" % (self.cidr_dir, self.timestamp)
        if not os.path.exists(self.directory_name):
            os.makedirs(self.directory_name)

    def getTimestamp(self):
        return self.timestamp

    def getLiveIPS(self):
        return self.liveIPs

    def getScanners(self):
        return self.scanners

    def arpscan(self):
        print("[ ARP scanning %s ]\n" % (self.CIDR))

        #Discover live hosts
        nm=nmap.PortScanner()
        nm_arp=nm.scan(hosts=self.CIDR,arguments="-sn")
        livehosts_file = open("%s/livehosts_%s" % (self.directory_name, self.cidr_dir), 'a+')

        for x in nm_arp.items()[1][1]:
            self.liveIPs.append(x)
            livehosts_file.write("%s\n" % x)

        print("%s live hosts on %s" % (len(self.liveIPs), self.CIDR))
        #self.liveIPs.remove(int_ip) # we dont need to scan ourself

    # def hostnames(self):
    #     warHostnames = Hostname()
    #     warHostnames.findHostnames(self.int_ip, self.CIDR, self.timestamp)
    #     self.hostnamesF["ips"]=warHostnames.getIPsGathered()
    #     self.hostnamesF["os"]=warHostnames.getOSGathered()
    #     self.hostnamesF["domains"]=warHostnames.getDomainsGathered()
    #     self.hostnamesF["hostnamesGathered"]=warHostnames.getHostnamesGathered()
    #     self.liveIPs=warHostnames.getLiveIPS()

    def scanning(self,status, intensity, iface):
        print("Starting single-threaded port scanner")
        scanner = targettedScanner()
        scanner.single_port_scanner(self.CIDR, intensity, iface, self.liveIPs, self.directory_name)
        self.scanners = scanner.scanners
        status.warberryOKGREEN("Completed Port Scanning")
        

    def enumerate(self,status, enumeration,iface):
        if enumeration == False:
            print("Enumerating services")

            # if we see a DNS server
            # check if 445 is enabled, and try enum4linux

            # 445 hosts, do SMB ping

            
#             if "Windows Hosts" in self.scanners:
#                 if len(self.scanners["Windows Hosts"]) > 0:
#                     windows_set = set(self.scanners["Windows Hosts"])
#                     self.scanners["Windows Hosts"] = list(windows_set)
#                     self.enumeration["shares_enum"] = shares_enum(iface, self.scanners["Windows Hosts"])
#                     status.warberryOKGREEN("Completed Enumerating Shares")
#                     self.enumeration["smb_users_enum"]=smb_users(iface, self.scanners["Windows Hosts"])
#                     status.warberryOKGREEN("Completed Enumerating Users")
#             if "NFS" in self.scanners:
#                 if len(self.scanners["NFS"]) > 0:
#                     nfs_set = set(self.scanners["NFS"])
#                     self.scanners["NFS"] = list(nfs_set)
#                     self.enumeration["nfs_enum"] = nfs_enum(iface, self.scanners["NFS"])
#                     status.warberryOKGREEN("Completed NFS Enumeration")
#             if "MySQL Databases" in self.scanners:
#                 if len(self.scanners["MySQL Databases"]) > 0:
#                     mysql_set = set(self.scanners["MySQL Databases"])
#                     self.scanners["MySQL Databases"] = list(mysql_set)
#                     self.enumeration["mysql_enum"] = mysql_enum(iface, self.scanners["MySQL Databases"])
#             if "MSSQL Databases" in self.scanners:
#                 if len(self.scanners["MSSQL Databases"]) > 0:
#                     mssql_set = set(self.scanners["MSSQL Databases"])
#                     self.scanners["MSSQL Databases"] = list(mssql_set)
#                     self.enumeration["mssql_enum"] = mssql_enum(iface, self.scanners["MSSQL Databases"])
#             if "SNMP" in self.scanners:
#                 if len(self.scanners["SNMP"]) > 0:
#                     snmp_set = set(self.scanners["SNMP"])
#                     self.scanners["SNMP_Unique"] = list(snmp_set)
#                     self.enumeration["snmp_enum"] = snmp_enum(iface, self.scanners["SNMP_Unique"])
#                     status.warberryOKGREEN("Completed SNMP Enumeration")
#             if "FTP" in self.scanners:
#                 if len(self.scanners["FTP"]) > 0:
#                     ftp_set = set(self.scanners["FTP"])
#                     self.scanners["FTP"] = list(ftp_set)
#                     self.enumeration["ftp_enum"] = ftp_enum(iface, self.scanners["FTP"])
#                     status.warberryOKGREEN("Completed FTP Enumeration")
#             if "VOIP" in self.scanners:
#                 if len(self.scanners["VOIP"]) > 0:
#                     voip_set = set(self.scanners["VOIP"])
#                     self.scanners["VOIP"] = list(voip_set)
#                     self.enumeration["sip_methods_enum"] = sip_methods_enum(iface, self.scanners["VOIP"])
#                     status.warberryOKGREEN("Completed SIP Methods Enumeration")
#                     self.enumeration["sip_users_enum"] = sip_users_enum(iface, self.scanners["VOIP"])
#                     status.warberryOKGREEN("Completed VOIP Enumeration")
#             webs=[]
#             if ("Web Servers Running on Port 80" in self.scanners) and (len(self.scanners["Web Servers Running on Port 80"])>0):
#                 for h in self.scanners["Web Servers Running on Port 80"]:
#                     webs.append(h.strip())
#             if "Web Servers Running on Port 8080" in self.scanners and (len(self.scanners["Web Servers Running on Port 8080"])>0):
#                 for h in self.scanners["Web Servers Running on Port 8080"]:
#                     webs.append(h.strip())
#             if "Web Servers Running on Port 443" in self.scanners and (len(self.scanners["Web Servers Running on Port 443"])>0):
#                 for h in self.scanners["Web Servers Running on Port 443"]:
#                     webs.append(h.strip())
#             if "Web Servers Running on Port 4443" in self.scanners and (len(self.scanners["Web Servers Running on Port 4443"])>0):
#                 for h in self.scanners["Web Servers Running on Port 4443"]:
#                     webs.append(h.strip())
#             if "Web Servers Running on Port 8081" in self.scanners and (len(self.scanners["Web Servers Running on Port 8081"])>0):
#                 for h in self.scanners["Web Servers Running on Port 8081"]:
#                     webs.append(h.strip())
#             if "Web Servers Running on Port 8181" in self.scanners and (len(self.scanners["Web Servers Running on Port 8181"])>0):
#                 for h in self.scanners["Web Servers Running on Port 8181"]:
#                     webs.append(h.strip())
#             if "Web Servers Running on Port 9090" in self.scanners and (len(self.scanners["Web Servers Running on Port 9090"])>0):
#                 for h in self.scanners["Web Servers Running on Port 9090"]:
#                     webs.append(h.strip())
#             self.scanners["Webservers"]=webs
#             if len(self.scanners["Webservers"])>0:
#                 webs_set = set(self.scanners["Webservers"])
#                 self.enumeration["Webservers_enum"] = list(webs_set)
# #            print(self.enumeration)
        else: 
            print("Skipping service enumeration")


    def namechange(self, hostnameOption, host_name):
        if (hostnameOption == True) and (host_name == 'WarBerry'):
            mvp_hosts = ['DEMO', 'DEV', 'PRINT', 'BACKUP', 'DC', 'DC1', 'DC2', 'SQL']
            hostname = socket.gethostname()
            mvp_found = False
            mvps=[]
            hosts=self.hostnamesF["hostnamesGathered"]
            for host in hosts:
                for mvp in mvp_hosts:
                    if host.strip() == mvp.strip():
                        print ("\n[+] Found interesting hostname %s\n" % mvp.strip())
                        mvps.append(host.strip())
                        mvp_found = True

            if mvp_found != True:
                print("\n[-] No interesting names found. Continuing with the same hostname")

            elif mvp_found == True:
		mvp_changed = False
                for mvp in mvps:
                    if mvp.strip() == hostname:
                        print("[*] Hostname is stealthy as is. Keeping the same!")
                    else:
			if mvp_changed == False:
				mvp_changed = True
                        	with open('/etc/hostname', 'w') as hostname:
                           		 hostname.write(mvp.strip())
                        	with open('/etc/hosts', 'w') as hosts:
                                    	print ("[*] Changing Hostname from " + socket.gethostname() + " to " + mvp)
                                    	hosts.write('127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\nff02::1\tip6-allnodes\nff02::2\tip6-allrouters\n\n127.0.1.1\t%s' % mvp.strip())
					#hosts.write('127.0.0.1\tlocalhost.localdomain\tlocalhost ip6-localhost\n127.0.1.1\t%s' % mvp.strip())
					subprocess.call('hostname %s' %mvp.strip(),shell=True)
                                    	subprocess.call('sudo systemctl daemon-reload 2>/dev/null', shell=True)
                                    	subprocess.call('sudo /etc/init.d/hostname.sh 2>/dev/null', shell=True)
                                    	print ("[+] New hostname: " + socket.gethostname())
				hosts.close()
				hostname.close()


