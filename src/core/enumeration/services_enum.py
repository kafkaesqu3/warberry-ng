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

import nmap
from src.utils.utils import *


def shares_enum(iface, hosts):
        print(" ")
        print("      [ SMB SHARES ENUMERATION MODULE ]\n")
        shares_res=[]
        for host in hosts:
            print ("[*]Enumerating shares on %s" %host.strip())
            nm = nmap.PortScanner()
            nm.scan(hosts=host, arguments='-Pn -T4 --script smb-enum-shares -p445 -e ' + iface + ' --open')
            result = nm.get_nmap_last_output()
            with open("Results/shares.xml", "w") as xmlfile:
                xmlfile.write(result)
                xmlfile.close()
                shares = XMLParser("Results/shares.xml")
                shares.pop(0)
                shares.pop(0)
                shares.pop(0)
                shares = shares[:-1]
                shares_res.append(shares)
        print("[+] Done! Results saved in warberry.db")
        return shares_res

def smb_finger(iface, hosts): 
    print("TODO")

# TODO: refactor SMB users to us enum4linux against targets
def smb_users(iface, hosts):
        print(" ")
        print("      [ SMB USERS ENUMERATION MODULE ]\n")
        users_res=[]
        for host in hosts:
            print ( + "[*] " + "Enumerating users on %s" %host.strip())
            nm = nmap.PortScanner()
            nm.scan(hosts=host, arguments='-Pn -T4 -sU -sS --script smb-enum-users -p U:137,T:139 -e ' + iface + ' --open')
            result = nm.get_nmap_last_output()
            with open("Results/smb_users.xml", "w") as xmlfile:
                xmlfile.write(result)
                xmlfile.close()
                users = XMLParser("Results/smb_users.xml")
                users.pop(0)
                users.pop(0)
                users.pop(0)
                users = users[:-1]
                users_res.append(users)
        print( + "[+] Done! Results saved in warberry.db")
        return users_res


def nfs_enum(iface, shares):
        print(" ")
        print("      [ NFS ENUMERATION MODULE ]\n")
        nfs_res=[]
        for share in shares:
            print( + "[*] " + "Enumerating NFS Shares on %s" %share.strip())
            nm = nmap.PortScanner()
            nm.scan(hosts=share, arguments='-Pn -sV -T4 --script afp-showmount -p111 -e ' + iface + ' --open')
            result = nm.get_nmap_last_output()
            with open("Results/nfs_enum.xml", "w") as xmlfile:
                xmlfile.write(result)
                xmlfile.close()
                nfs = XMLParser("Results/nfs_enum.xml")
                nfs.pop(0)
                nfs.pop(0)
                nfs.pop(0)
                nfs = nfs[:-1]
                nfs_res.append(nfs)
        print( + "[+] Done! Results saved in warberry.db")
        return nfs_res

def mysql_enum(iface, dbs):
    print(" ")
    print("      [ MYSQL ENUMERATION MODULE ]\n")
    mysql_res=[]
    for db in dbs:
        print("[*] Enumerating MYSQL DB on %s" %db.strip())
        nm = nmap.PortScanner()
        nm.scan(hosts=db, arguments='-Pn -T4 -sV --script mysql-enum -p3306 -e ' + iface + ' --open')
        result = nm.get_nmap_last_output()
        with open("Results/mysql_enum.xml", "w") as xmlfile:
            xmlfile.write(result)
            xmlfile.close()
            mysql = XMLParser("Results/mysql_enum.xml")
            mysql.pop(0)
            mysql.pop(0)
            mysql.pop(0)
            mysql = mysql[:-1]
            mysql_res.append(mysql)
    print( + "[+] Done! Results saved in warberry.db")
    return mysql_res


def mssql_enum(iface,dbs):
    print(" ")
    print("      [ MSSQL ENUMERATION MODULE ]\n")
    mssql_res=[]
    for db in dbs:
        print ("[*] Enumerating MSSQL DB on %s" %db.strip())
        nm = nmap.PortScanner()
        nm.scan(hosts=db, arguments='-Pn -T4 -sV --script ms-sql-info -p1433 -e ' + iface + ' --open')
        result = nm.get_nmap_last_output()
        with open("Results/mssql_enum.xml", "w") as xmlfile:
            xmlfile.write(result)
            xmlfile.close()
            mssql = XMLParser("Results/mssql_enum.xml")
            mssql.pop(0)
            mssql.pop(0)
            mssql.pop(0)
            mssql = mssql[:-1]
            mssql_res.append(mssql)
    print( + "[+] Done! Results saved in warberry.db")
    return mssql_res


def ftp_enum(iface,ftps):
    print(" ")
    print("      [ ANON FTP ENUMERATION MODULE ]\n")
    ftp_res=[]
    for ftp in ftps:
        print ( + "[*] " + "Enumerating FTP on %s" %ftp.strip())
        nm = nmap.PortScanner()
        nm.scan(hosts=ftp, arguments='-Pn -T4 -sV --script ftp-anon -p22 -e ' + iface + ' --open')
        result = nm.get_nmap_last_output()
        with open("Results/ftp_enum.xml", "w") as xmlfile:
            xmlfile.write(result)
            xmlfile.close()
            ftpF = XMLParser('Results/ftp_enum.xml')
            ftpF.pop(0)
            ftpF.pop(0)
            ftpF.pop(0)
            ftpF = ftpF[:-1]
            ftp_res.append(ftpF)
    print( + "[+] Done! Results saved in warberry.db")
    return ftp_res


def snmp_enum(iface,snmps):
    print(" ")
    print("      [ SNMP ENUMERATION MODULE ]\n")
    snmp_res=[]
    for snmp in snmps:
        print ( + "[*] " + "Enumerating SNMP on %s" %snmp.strip())
        nm = nmap.PortScanner()
        nm.scan(hosts=snmp, arguments='-Pn -T4 -sV -sU -p161 -e ' + iface + ' --open')
        result = nm.get_nmap_last_output()
        with open("Results/snmp_enum.xml", "w") as xmlfile:
            xmlfile.write(result)
            xmlfile.close()
            snmpF = XMLParser("Results/snmp_enum.xml")
            snmpF.pop(0)
            snmpF.pop(0)
            snmpF.pop(0)
            snmpF = snmpF[:-1]
            snmpResult={}
            address={}
#            address["ipv4"]=snmpF[0]["addresses"][0]["addr"]
 #           address["mac"]=snmpF[0]["addresses"][1]["addr"]
  #          address["vendor"]=snmpF[0]["addresses"][1]["vendor"]
  #          snmpResult["Address"]=address
            snmp_res.append(snmpResult)
    print ( + "[+] Done! Results saved in warberry.db")
    return snmp_res

def sip_methods_enum(iface,sips):
    print(" ")
    print("      [ SIP METHODS ENUMERATION MODULE ]\n")
    sip_m_res=[]
    for sip in sips:
        print ( + "[*] " + "Enumerating SIP Methods on %s" %sip.strip())
        nm = nmap.PortScanner()
        nm.scan(hosts=sip, arguments='-Pn -T4 --script sip-methods -sU -e ' + iface + ' -p 5060')
        result = nm.get_nmap_last_output()
        with open("Results/sip_methods.xml", "w") as xmlfile:
            xmlfile.write(result)
            xmlfile.close()
            sip_m = XMLParser("Results/sip_methods.xml")
            sip_m.pop(0)
            sip_m.pop(0)
            sip_m.pop(0)
            sip_m = sip_m[:-1]
            sip_m_res.append(sip_m)
    print ( + "[+] Done! Results saved in warberry.db")
    return sip_m_res

def sip_users_enum(iface,sips):
    print (" ")
    print ("      [ SIP USERS ENUMERATION MODULE ]\n")
    sip_u_res=[]
    for sip in sips:
        print ( + "[*] " + "Enumerating SIP Users on %s" %sip.strip())
        nm = nmap.PortScanner()
        nm.scan(hosts=sip, arguments='-Pn -T4 --script sip-enum-users -sU -e ' + iface + ' -p 5060')
        result = nm.get_nmap_last_output()
        with open("Results/sip_users.xml", "w") as xmlfile:
            xmlfile.write(result)
            xmlfile.close()
            sip_u = XMLParser("Results/sip_users.xml")
            sip_u.pop(0)
            sip_u.pop(0)
            sip_u.pop(0)
            sip_u = sip_u[:-1]
            sip_u_res.append(sip_u)
    print ( + "[+] Done! Results saved in warberry.db")
    return sip_u_res
