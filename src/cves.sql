CREATE TABLE CVES (

ID VARCHAR(20) PRIMARY KEY,

Description VARCHAR(500),

Date DATE,

Score DECIMAL(3,2),

Kind_of_vulnerability VARCHAR(500),

Vulnerable_products VARCHAR(500),

Solution VARCHAR(500)

);
