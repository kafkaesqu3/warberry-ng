#!/bin/bash

if [ "$EUID" -ne 0 ]
	then echo "Must be root"
	exit
fi

apt-get remove --purge hostapd -yqq

apt-get update -yqq
apt-get upgrade -yqq

apt-get install hostapd dnsmasq -yqq
apt-get install dnsmasq hostapd

systemctl stop dnsmasq
systemctl stop hostapd

reboot

# cat << EOF >> /etc/dhcpcd.conf
# interface wlan0
#     static ip_address=10.10.100.5/24
#     nohook wpa_supplicant
# EOF

echo "Configuring dnsmasq"
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig  
cat << EOF >> /etc/dnsmasq.conf
interface=wlan0
  dhcp-range=10.10.100.100,10.10.100.254,255.255.255.0,24h
EOF

echo "Configuring hostapd"
cat <<EOF>> /etc/hostapd/hostapd.conf
interface=wlan0
driver=nl80211
ssid=raspberrypi
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
# wpa=2
# wpa_passphrase=peekaboo
# wpa_key_mgmt=WPA-PSK
# wpa_pairwise=TKIP
# rsn_pairwise=CCMP
EOF

sed -i -- 's/allow-hotplug wlan0//g' /etc/network/interfaces
sed -i -- 's/iface wlan0 inet manual//g' /etc/network/interfaces
sed -i -- 's/    wpa-conf \/etc\/wpa_supplicant\/wpa_supplicant.conf//g' /etc/network/interfaces
sed -i -- 's/#DAEMON_CONF=""/DAEMON_CONF="\/etc\/hostapd\/hostapd.conf"/g' /etc/default/hostapd
# sed -i 's/^.*DAEMON_CONF.*/DAEMON_CONF="\/etc\/hostapd\/hostapd.conf"/g' /etc/default/hostapd   

echo "Configuring static network interface"
cat <<EOF>> /etc/network/interfaces

allow-hotplug wlan0
iface wlan0 inet static# iface wlan0 inet static
address 10.10.100.1
netmask 255.255.255.0
network 10.10.100.0
broadcast 10.10.100.255
EOF

echo "denyinterfaces wlan0" >> /etc/dhcpcd.conf
# 
# service networking restart

systemctl unmask hostapd.service

systemctl enable hostapd
systemctl enable dnsmasq

systemctl start hostapd
systemctl start dnsmasq

echo "All done! Rebooting"
reboot 0

#sysctl net.ipv4.ip_forward=1

#sudo iptables -t nat -A  POSTROUTING -o eth0 -j MASQUERADE
#sudo sh -c "iptables-save > /etc/iptables.ipv4.nat"
#iptables-restore < /etc/iptables.ipv4.nat