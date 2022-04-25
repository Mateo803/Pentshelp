import subprocess

from os import path



def detect_vulnerabilities(target, output):


    if output is None:


        vulnerabilities = subprocess.Popen(['nmap', '--script', 'nmap-vulners','-sV',target,], stdout=subprocess.PIPE)

        subprocess.run(['grep', 'CVE'], stdin=vulnerabilidades.stdout, stdout=None)


    else:


        file = open(output,'w')

        subprocess.Popen(['nmap', '--script', 'nmap-vulners','-sV',target,], stdout=None)
        

        subprocess.run(['grep', 'http'], stdin=vulnerabilities.stdout, stdout=file)
        
        
        if path.exists(output):
               
            print('File created successfully');
            
        else:
            
            print('An error ocurred while creating the file')

