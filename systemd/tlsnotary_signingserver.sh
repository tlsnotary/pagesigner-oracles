#!/bin/sh -e

#this script is run by systemd under User=sigserver

python3 /dev/shm/signing_server.py
