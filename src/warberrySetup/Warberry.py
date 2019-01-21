from src.warberrySetup.WarberryArgs import *
from src.warberrySetup.WarberryInformationGatherer import *
from src.warberrySetup.WarberryStatus import *
from src.utils.utils import *
from src.core.exploits.Responder import *
from src.core.enumeration.network_packets import *
import time
import datetime

import os,sys
import signal

class Warberry:

    def __init__(self,parser):
        self.internal_ip=""
        self.netmask=""
        self.CIDR=""
        self.external_ip=""
        self.gateway=""
        self.dns=""


        # timestamp of run to mark files
        self.timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S')
        self.status = WarberryStatus()
        start=int(time.time())
        #If not sudo
        if not os.geteuid() == 0:
            self.status.warberryFAIL("*** You are not running as root and some modules will fail ***\nRun again with sudo.")
            sys.exit(-1)

        dhcp_check(self.status)


        #Initialize arguments and information Gathering
        self.warberryArgs = WarberryArgs(parser)
        
        #Execute Responder
        #if (self.warberryArgs.getMalicious == True):
        #    print("Starting responder poisoning for local subnet")
        #    pid = subprocess.Popen(["sudo","python","run_responder.py",timestamp,str(self.warberryArgs.getInterface())]) # call subprocess
        
    
        # Set variables for warberry execution against LAN
        self.setNetmask(self.warberryArgs.getInterface())
        self.setInternalIP(self.warberryArgs.getInterface())
        self.setCIDR()
        self.setExternalIP()
        #warberryDB.updateStatus("Completed localhost network information gathering")
        
        print("Local subnet: %s" % self.CIDR)
        self.subnetInformationGatherer = WarberryInformationGatherer(self.CIDR, self.timestamp)


        if self.internal_ip is None:
            print("No IP address on %s detected, exiting" % self.warberryArgs.getInterface())
            exit
        else:
            #warberryDB.updateElements(self.subnetInformationGatherer)
            #warberryDB.insertcommonWarInfo()
            self.pcap(self.status, self.warberryArgs.getInterface(),
                                                   self.warberryArgs.getPackets(), self.warberryArgs.getExpire())
            
            self.subnetInformationGatherer.arpscan()

            #self.subnetInformationGatherer.hostnames()
            #warberryDB.updateElements(self.subnetInformationGatherer)
            #warberryDB.insertLiveIPS()
            #warberryDB.updateStatus("Completed Scope Definition Module")
            #warberryDB.insertHostnamesF()
            #self.subnetInformationGatherer.namechange(self.warberryArgs.getHostname(), self.warberryArgs.getName())

            if self.warberryArgs.getRecon() == False:
                # recon mode = port scanning
                print("Starting recon mode: port scanning subnet")

                self.subnetInformationGatherer.scanning(self.status, self.warberryArgs.getIntensity(),
                                                       self.warberryArgs.getInterface())
                #warberryDB.updateStatus("Completed Scanning Module")
                # TODO add flag for service enumeration
                if self.warberryArgs.getEnumeration() == False:
                    print("Service enumeration on ports identified as open")

                    self.subnetInformationGatherer.enumerate(self.status, self.warberryArgs.getEnumeration(), self.warberryArgs.getInterface())
                else: 
                    print("Skipping enumeration mode")    
            else: 
                print("Skipping recon mode")

        

        FinishTime=start+int(self.warberryArgs.getTime())
        #print ("Waiting for Responder ...")
        #current=int (time.time())
        #while (current<FinishTime):
        #    current=int(time.time())
    
        #responderResults=Responder()
        #hashes=responderResults.retrieveHashes()
        #if (len(hashes)>0):
        #    warberryDB.saveHashes(hashes)

        #warberryDB.updateEndTime()
        
        #p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
        #out, err = p.communicate()
        #for line in out.splitlines():
        #    if 'python' in line:
        #        pid = int(line.split(None, 1)[0])
#        os.kill(pid, signal.SIGKILL)


    def pcap(self,status, iface, packets, expire):
        sniffer(status, iface, packets, expire)

    def setExternalIP(self):
        self.external_ip=external_IP_recon()
        if (self.external_ip==None):
            print("[!] Could not reach the outside world. Possibly behind a firewall or some kind filtering\n")
        else:
            print('[+] External IP obtained: %s\n' %self.external_ip)

    def setInternalIP(self, iface):
        self.internal_ip = iprecon(iface, self.netmask)

    def setNetmask(self,iface):
        self.netmask = netmask_recon(iface)

    def setCIDR(self):
        self.CIDR=subnet(self.internal_ip,self.netmask)











