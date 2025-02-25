#!/bin/bash

mkdir /bak
cd /bak

tar -zcvf init_home.tar.gz /home

cat /etc/passwd > init_passwd
cat /etc/group > init_group
systemctl list-units > init_systemctl
lsmod > init_lsmod
last > init_last

echo "bakk'd everything up"
echo "don't tell red team ;)"
