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

First execute install_requeriments.sh and create_pentesting_folders.sh

```sh
chmod +x install_requeriments.sh create_pentesting_folders.sh
./requeriments.sh
./create_pentesting_folders.sh
```

Now simply execute pentshelp.py with python3

```
python3 pentshelp.py option argument
```

## Configuring MySQL (reporting)

In order to use the reporting funcionality, you need to follow these steps:

- Install MySQL
- Create a user named Pentshelp with a strong password (hostname is localhost).
Note:  Remember to insert the password into the reporting.py script in order to connect to the database.
- Create a database named pentshelp and insert into it the CVES table (whose code is in src/cves.sql file)
- Finally, grant all privileges to the user Pentshelp on the CVES table


The following code does the above (assuming the program is installed and you are the root user):

create database pentshelp;

use pentshelp;

CREATE TABLE CVES (

ID VARCHAR(20) PRIMARY KEY,

Name VARCHAR(500),

Date DATE,

Score DECIMAL(3,2),

Kind_of_vulnerability VARCHAR(500),

Vulnerable_products VARCHAR(500),

Solution VARCHAR(500)

);

create user 'Pentshelp'@'localhost' identified by 'strong_password';

grant all privileges on pentshelp.CVES to 'Pentshelp'@'localhost';

flush privileges;
