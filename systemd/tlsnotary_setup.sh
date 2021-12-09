#!/bin/sh -e

apt -qq update
apt install -y nodejs haveged
# give haveged some time to collect entropy
sleep 5
wget --no-verbose https://golang.org/dl/go1.17.3.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.3.linux-amd64.tar.gz
cd /home/ubuntu/server/src
export GOPATH=/home/ubuntu
export HOME=/home/ubuntu
export GOROOT=/usr/local/go
/usr/local/go/bin/go mod init notary
/usr/local/go/bin/go get github.com/bwesterb/go-ristretto@b51b4774df9150ea7d7616f76e77f745a464bbe3
/usr/local/go/bin/go get github.com/roasbeef/go-go-gadget-paillier@14f1f86b60008ece97b6233ed246373e555fc79f
/usr/local/go/bin/go get golang.org/x/crypto/blake2b
/usr/local/go/bin/go get golang.org/x/crypto/nacl/secretbox
/usr/local/go/bin/go build -o notary

# because we modified cloud init modules, there will be no user ubuntu at this point
adduser --disabled-password --gecos "" ubuntu
chown -R ubuntu:ubuntu /home/ubuntu/
usermod -a -G tty ubuntu #allow user ubuntu to print to tty

# setup an encrypted swap
fallocate -l 1G /cryptswap
echo "cryptswap /cryptswap /dev/urandom swap,cipher=aes-xts-plain64" >> /etc/crypttab
echo "/dev/mapper/cryptswap none swap sw 0 0" >> /etc/fstab
cryptdisks_start cryptswap
swapon -a

#assign random passwords for good measure
#dont use "cat /dev/urandom | base64" because we can get a Broken pipe error
random1="$(dd if=/dev/urandom bs=200 count=1)"
random2="$(dd if=/dev/urandom bs=200 count=1)"
pass1="$(echo $random1 | base64 | head -c 20)"
pass2="$(echo $random2 | base64 | head -c 20)"
echo ubuntu:$pass1 | chpasswd
echo root:$pass2 | chpasswd

#using -I to insert rules to the top of the list, i.e. they will appear in iptables in reverse order
#allow only port 10011 and 10012 and localhost
iptables -I INPUT -j DROP
# allow time sync with AWS's NTP listening on link-local address
iptables -I INPUT -s 169.254.169.123 -j ACCEPT
iptables -I INPUT -p tcp --dport 10011 -j ACCEPT
iptables -I INPUT -p tcp --dport 10012 -j ACCEPT
#anti DoS: allow no more than 6 new connections every 40 seconds
iptables -I INPUT -p tcp --dport 10011 -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport 10011 -m state --state NEW -m recent --update --seconds 40 --hitcount 6 -j DROP
iptables -I INPUT -i lo -j ACCEPT

touch /home/ubuntu/setupdone
# as soon as public.key appears, print it and exit
/bin/bash -c 'FILE=/home/ubuntu/server/src/public.key; until [ -f $FILE ]; do sleep 1; done; echo "PageSigner public key for verification"; sleep 3; cat $FILE; sleep 3; exit'
