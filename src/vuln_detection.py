import subprocess


def detect_vulnerabilities(target, output):


    if output is False:


        vulnerabilities = subprocess.Popen(['nmap', '-sV', '--script','vulners',target], stdout=None)

        
    else:


        file = open('pentesting_files/vulnerabilities/cves.txt','w')

        vulnerabilities = subprocess.Popen(['nmap', '-sV', '--script','vulners',target], stdout=file)
    
        print('\nFile created successfully in pentesting_files/vulnerabilities/cves.txt')
