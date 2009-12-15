#!/bin/sh
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/lulznet/key -out /etc/lulznet/cert.pem

