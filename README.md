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
node app
```

Now simply execute pentshelp.py with python3

```sh
python3 pentshelp.py option argument
```
