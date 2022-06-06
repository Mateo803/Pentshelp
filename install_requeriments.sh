#!/bin/bash

sudo apt-get update &&

sudo apt-get install python &&

sudo apt-get install nmap -y && 

sudo apt-get install gobuster -y;

pip install argparse mysql-connector-python reportlab matplotlib;

echo -e "$(tput setaf 3) \nRequeriments installed succesfully"
