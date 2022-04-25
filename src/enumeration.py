import subprocess

from os import path

def detect_ports(target, output):

                
        if output is None:
        
            print('\nOpened ports:\n')

            puertos_abiertos = subprocess.Popen(['nmap', '-sV', target], stdout=subprocess.PIPE)
                    
            subprocess.run(['grep', 'open'], stdin=puertos_abiertos.stdout, stdout=None)
            
           
        else:


            file = open(output,'w')

            puertos_abiertos = subprocess.Popen(['nmap', '-sV', target], stdout=subprocess.PIPE)
            
            subprocess.run(['grep', 'open'], stdin=puertos_abiertos.stdout, stdout=file)
            
            if path.exists(output):
               
                print('File created successfully');
                
            else:
                
                print('An error ocurred while creating the file')



def detect_os(target, output):

    if output == None:
            
            operating_system = subprocess.Popen(['sudo', 'nmap', '-O', target], stdout=subprocess.PIPE)

            subprocess.run(['grep', 'OS details'], stdin=operating_system.stdout, stdout=None)
            
            
    else:
        

        file = open(output,'w')
        
        operating_system = subprocess.Popen(['sudo', 'nmap', '-O', target], stdout=subprocess.PIPE)

        subprocess.run(['grep', 'OS details'], stdin=operating_system.stdout, stdout=file)
        
        if path.exists(output):
               
            print('File created successfully');
            
        else:
            
            print('An error ocurred while creating the file')


def detect_directories(target, wordlist, output):

    if output is None:

        subprocess.Popen(['gobuster','dir','-u',target,'-w',wordlist], stdout=None)


    else:
        

        file = open(output,'w')
        
        directories = subprocess.Popen(['gobuster','dir','-u',target,'-w',wordlist], stdout=None)

        subprocess.run(['grep', 'http'], stdin=directories.stdout, stdout=file)
        
        if path.exists(output):
               
            print('File created successfully');
            
        else:
            
            print('An error ocurred while creating the file')



def detect_subdirectories(target, wordlist, output):

    if output is None:

        subprocess.Popen(['gobuster','dns','-d',target,'-w',wordlist], stdout=None)


    else:
        

        file = open(output,'w')
        
        subdomains = subprocess.Popen(['gobuster','dns','-d',target,'-w',wordlist], stdout=None)

        subprocess.run(['grep', 'http'], stdin=subdomains.stdout, stdout=file)
        
        if path.exists(output):
               
            print('File created successfully');
            
        else:
            
            print('An error ocurred while creating the file')



def add_host(hostname, ip):


        sed_process= "1i" + ip + "    " + hostname 

        subprocess.run(['sudo','sed','-i',sed_process,'/etc/hosts'], stdout=None)





