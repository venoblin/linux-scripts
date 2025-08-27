#!/bin/bash
#Reboots homelab and scrubs snap raid

sudo snapraid scrub -p 100

sudo shutdown -r now