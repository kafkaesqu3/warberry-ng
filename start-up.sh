#!/bin/bash

nmcli radio wifi off
rfkill unblock wlan
ifconfig wlan0 10.10.100.1 netmask 255.255.255.0 up
sleep 1
service hostapd restart
service dnsmasq restart
# Routing
# sysctl net.ipv4.ip_forward=1
# NAT
# iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
hostapd /etc/hostapd.conf
# Wait for STRG+C
# Restore NAT
# iptables -D POSTROUTING -t nat -o eth0 -j MASQUERADE
# Restore Routing
# sysctl net.ipv4.ip_forward=0
# Stop Services
service dnsmasq stop
service hostapd stop