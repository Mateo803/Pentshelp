import subprocess

from os import path

def detect_ports(target, output):

                
        if output is False:
        
            print('\nOpened ports:\n')

            puertos_abiertos = subprocess.Popen(['nmap', '-sV', target], stdout=subprocess.PIPE)
                    
            subprocess.run(['grep', 'open'], stdin=puertos_abiertos.stdout, stdout=None)
            
           
        else:

            if path.exists('pentesting_files'):


                file = open('pentesting_files/enumeration/open_ports.txt','w')

                puertos_abiertos = subprocess.Popen(['nmap', '-sV', target], stdout=subprocess.PIPE)
                
                subprocess.run(['grep', 'open'], stdin=puertos_abiertos.stdout, stdout=file)
            
                print('\nFile created successfully in pentesting_files/enumeration/open_ports.txt');
                

            else:
                
                print('\nYou need to create the pentshelp folders first')



def detect_os(target, output):

    if output is False:
            
            operating_system = subprocess.Popen(['sudo', 'nmap', '-O', target], stdout=subprocess.PIPE)

            subprocess.run(['grep', 'OS details'], stdin=operating_system.stdout, stdout=None)
            
            
    else:

        if path.exists('pentesting_files'):


            file = open('pentesting_files/enumeration/os.txt','w')

            operating_system = subprocess.Popen(['sudo', 'nmap', '-O', target], stdout=subprocess.PIPE)

            subprocess.run(['grep', 'OS details'], stdin=operating_system.stdout, stdout=file)
        
            print('\nFile created successfully in pentesting_files/enumeration/os.txt');
            

        else:
            
            print('\nYou need to create the pentshelp folders first')


def detect_directories(target, wordlist, output):

    if output is False:

        subprocess.Popen(['gobuster','dir','-u',target,'-w',wordlist], stdout=None)


    else:

        if path.exists('pentesting_files'):


            file = open('pentesting_files/enumeration/directories.txt','w')

            directories = subprocess.Popen(['gobuster','dir','-u',target,'-w',wordlist], stdout=None)

            subprocess.run(['grep', 'http'], stdin=directories.stdout, stdout=file)
        
            print('\nFile created successfully in pentesting_files/enumeration/directories.txt');
            

        else:
            
            print('\nYou need to create the pentshelp folders first')



def detect_subdomains(target, wordlist, output):

    if output is False:

        subprocess.Popen(['gobuster','dns','-d',target,'-w',wordlist], stdout=None)


    else:

        if path.exists('pentesting_files'):


            file = open('pentesting_files/enumeration/subdomains.txt','w')

            directories = subprocess.Popen(['gobuster','dir','-d',target,'-w',wordlist], stdout=None)

            subprocess.run(['grep', 'http'], stdin=subdomains.stdout, stdout=file)
        
            print('\nFile created successfully in pentesting_files/enumeration/subdomains.txt');
            

        else:
            
            print('\nYou need to create the pentshelp folders first')



def add_host(hostname, ip):


        sed_process= "1i" + ip + "    " + hostname 

        subprocess.run(['sudo','sed','-i',sed_process,'/etc/hosts'], stdout=None)
