#!/bin/sh -e

#create two users
adduser --disabled-password --gecos "" notary
usermod -a -G tty notary #allow notaryserver.py to print to tty
adduser --disabled-password --gecos "" sigserver

#dont use pipes with urandom e.g. "cat /dev/urandom | base64" because we can get a Broken pipe error
random1="$(dd if=/dev/urandom bs=200 count=1)"
random2="$(dd if=/dev/urandom bs=200 count=1)"
random3="$(dd if=/dev/urandom bs=200 count=1)"
pass1="$(echo $random1 | base64 | head -c 20)"
pass2="$(echo $random2 | base64 | head -c 20)"
pass3="$(echo $random3 | base64 | head -c 20)"

#assign random passwords for good measure
echo notary:pass1 | chpasswd
echo sigserver:pass2 | chpasswd
#changing password for ubuntu gives error: chpasswd: (user ubuntu) pam_chauthtok() failed
#TODO find out how to get around this error
#echo ubuntu:pass3 | chpasswd

sudo -u sigserver openssl ecparam -genkey -name prime256v1 -noout -out /dev/shm/private.pem
#private key readable only by sigserver user
sudo -u sigserver chmod 0400 /dev/shm/private.pem
sudo -u sigserver openssl ec -in /dev/shm/private.pem -pubout -out /dev/shm/public.pem
echo "PageSigner public key for verification"
cat /dev/shm/public.pem

#I got weird permission errors when trying to access files in /home/ubuntu with sudo -u ubuntu
#That's why I'm copying them to /dev/shm

cp -R /root/notary /dev/shm
chmod -R 777 /dev/shm/notary
chown -R notary:notary /dev/shm/notary

cp /root/signing_server/signing_server.py /dev/shm/signing_server.py
chmod 777 /dev/shm/signing_server.py
chown sigserver:sigserver /dev/shm/signing_server.py

#using -I to insert rules to the top of the list, i.e. they will appear in iptables in reverse order
#allow only port 10011 and localhost
iptables -I INPUT -j DROP
iptables -I INPUT -p tcp --dport 10011 -j ACCEPT
#anti DoS: allow no more than 20 new connections every 40 seconds
iptables -I INPUT -p tcp --dport 10011 -m state --state NEW -m recent --set
#xt_recent cant do more than 20 by default
iptables -I INPUT -p tcp --dport 10011 -m state --state NEW -m recent --update --seconds 40 --hitcount 20 -j DROP
iptables -I INPUT -i lo -j ACCEPT