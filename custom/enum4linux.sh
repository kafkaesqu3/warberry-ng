nmap --script broadcast-dhcp-discover >> /root/dhcp-discover.txt
dns=`grep "Domain Name Server" /root/dhcp-discover.txt`
dnsserver1=`echo $dns | cut -d " " -f 5 | tr -d ','` 
dnsserver2=`echo $dns | cut -d " " -f 6 | tr -d ','` 


domain=`grep "Domain Name:" /root/dhcp-discover.txt`
domainname=`echo $domain | cut -d":" -f 2 | tr -d " "`

nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='$domainname'" >> /root/dns-srv-enum.txt

enum4linux -a $dnsserver1 >> /root/enum4linux-dns1.txt
enum4linux -a $dnsserver2 >> /root/enum4linux-dns2.txt