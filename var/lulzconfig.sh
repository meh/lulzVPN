#!/bin/sh
echo "Insert username: "
read user
echo "Insert tap address: "
read tap_addr

if [[ ! -e /etc/lulznet ]]
then
mkdir /etc/lulznet
fi

echo user $user >> /etc/lulznet/config
echo tap_addr $tap_addr >> /etc/lulznet/config
echo tap_netm 255.255.255.0 >> /etc/lulznet/config
echo interactive yes >> /etc/lulznet/config
echo listening yes >> /etc/lulznet/config
echo debug 2 >> /etc/lulznet/config

openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/lulznet/key -out /etc/lulznet/cert.pem
