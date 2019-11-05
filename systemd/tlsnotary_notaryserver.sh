#!/bin/sh -e

#this script is run by systemd under User=notary

python3 /dev/shm/notary/notaryserver.py
