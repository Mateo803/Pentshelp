# Pensthelp
    
Pentesting semi-automatic tool which eases this process through distinct type of scripts.


## Features

- Enumeration: operating system, open ports, services, etc.
- Vulnerabilities detection
- Vulnerabilities exploitation
- Postexploitation (privilege escalation)
- Report generation


## Requeriments

- GNU/Linux operating system (tested on Kali Linux)
- Python 3.x and pip3
- Having superuser privileges (many functions require that)
- Advanced Packaging Tool (if your operating system doesn´t have it)
- Specific software listed in install_requeriments.sh


## Installation

First execute install_requeriments.sh

```sh
chmod +x install_requeriments.sh
./requeriments.sh
```

Now simply execute pentshelp.py with python3

```
python3 pentshelp.py option argument
```

## Configuring MySQL (reporting)

In order to use the reporting funcionality, you need to follow these steps:

- Install MySQL
- Create an user named pentshelp with password Pentshelp_passw0rd
- Create a database named pentshelp
- In this database copy and run cve.py (which is in src folder). This will create the CVE table
- The host is localhost
