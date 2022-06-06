import subprocess

from os import path

def detect_ports(target, output):

                
        if output is False:
        
            print('\nOpened ports:\n')

            open_ports = subprocess.Popen(['nmap', '-sV', target], stdout=subprocess.PIPE)
                    
            subprocess.run(['grep', 'open'], stdin=open_ports.stdout, stdout=None)
            
           
        else:

    
            file = open('pentesting_files/enumeration/open_ports.txt','w')

            open_ports = subprocess.Popen(['nmap', '-sV', target], stdout=subprocess.PIPE)
            
            subprocess.run(['grep', 'open'], stdin=open_ports.stdout, stdout=file)
        
            print('\nFile created successfully in pentesting_files/enumeration/open_ports.txt');
                


def detect_os(target, output):

    if output is False:
            
            operating_system = subprocess.Popen(['sudo', 'nmap', '-O', target], stdout=subprocess.PIPE)

            subprocess.run(['grep', 'OS details'], stdin=operating_system.stdout, stdout=None)
            
            
    else:

        
        file = open('pentesting_files/enumeration/os.txt','w')

        operating_system = subprocess.Popen(['sudo', 'nmap', '-O', target], stdout=subprocess.PIPE)

        subprocess.run(['grep', 'OS details'], stdin=operating_system.stdout, stdout=file)
    
        print('\nFile created successfully in pentesting_files/enumeration/os.txt');
            

def detect_directories(target, wordlist, output):

    if output is False:

        subprocess.Popen(['gobuster','dir','-u',target,'-w',wordlist], stdout=None)


    else:

       
        file = open('pentesting_files/enumeration/directories.txt','w')

        directories = subprocess.Popen(['gobuster','dir','-u',target,'-w',wordlist], stdout=None)

        subprocess.run(['grep', 'http'], stdin=directories.stdout, stdout=file)
    
        print('\nFile created successfully in pentesting_files/enumeration/directories.txt');
            


def detect_subdomains(target, wordlist, output):

    if output is False:

        subprocess.Popen(['gobuster','dns','-d',target,'-w',wordlist], stdout=None)


    else:

        file = open('pentesting_files/enumeration/subdomains.txt','w')

        directories = subprocess.Popen(['gobuster','dir','-d',target,'-w',wordlist], stdout=None)

        subprocess.run(['grep', 'http'], stdin=subdomains.stdout, stdout=file)
    
        print('\nFile created successfully in pentesting_files/enumeration/subdomains.txt');
            


def add_host(hostname, ip):


        sed_process= "1i" + ip + "    " + hostname 

        subprocess.run(['sudo','sed','-i',sed_process,'/etc/hosts'], stdout=None)
