import subprocess

from os import path



def detect_vulnerabilities(target, output):


    if output is False:


        vulnerabilities = subprocess.Popen(['nmap', '-sV', '--script','vulners',target], stdout=None)

        
    else:

        if path.exists('pentesting_files'):


            file = open('pentesting_files/vulnerabilities/cves.txt','w')

            vulnerabilities = subprocess.Popen(['nmap', '-sV', '--script','vulners',target], stdout=file)
        
            print('\nFile created successfully in pentesting_files/vulnerabilities/cves.txt')


        else:
            
            print('\nYou need to create the pentshelp folders first')
