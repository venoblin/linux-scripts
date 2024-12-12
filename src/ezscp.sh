#!/bin/bash
#moves items from current machine to another using scp

current_machine=$(whoami)@$(hostname).local

echo $current_machine