#!/bin/bash

sudo apt-get update &&

sudo apt-get install python3 &&

sudo apt-get install nmap -y && 

sudo apt-get install gobuster -y;

pip install argparse mysql-connector-python reportlab matplotlib;

echo "$(tput setaf 3) \nRequeriments installed succesfully"
