try:

    import argparse
    from os import path
    import src.enumeration
    import src.vuln_detection
    import src.exploitation
    import src.postexploitation
    import src.reporting
    
    
except:

    print('\nThere are dependencies not installed. Please execute install_dependencies.sh first')
    
    exit()


if not path.exists('pentesting_files'):

    print('\nYou need to create the pentshelp folders first')

    exit()
    

def main():

    parser = argparse.ArgumentParser(prog="pentshelp", description="Semi-automatic pentesting tool which speeds up many common tasks related to this technique")

    #Enumeration options

    parser.add_argument("-p","--ports", help="Shows open ports on the selected target",metavar=('TARGET'))

    parser.add_argument("--os", help="Shows the operating system of the selected target",metavar=('TARGET'))

    parser.add_argument("--directories", help="Shows the directories of the select target (web server)", nargs=2,metavar=('TARGET','WORDLIST'))

    parser.add_argument("--subdomains", help="Shows the subdomains of the select target (web server)", nargs=2,metavar=('TARGET','WORDLIST'))

    parser.add_argument("-a","--add_host",help="Adds hostname to /etc/hosts", nargs=2,metavar=('TARGET_HOSTNAME','TARGET_IP'))


    #Vulnerabilities detection option

    parser.add_argument("--vulnerabilities",help="Detect possible vulnerabilities on the selected target",metavar=('TARGET'))


    #Exploitation option

    parser.add_argument("-u","--upload_exploit",help="Uploads an exploit to the target machine", nargs=3,metavar=('REPOSITORY','USER_TARGET','TARGET'))


    #Postexploitation option

    parser.add_argument("--pe",help="Detects vulnerabilities related to privilege scalation",metavar=('TARGET'))


    #Reporting options

    parser.add_argument("-r","--report",help="Reports a vulnerability (CVE) with an optional solution read from a text file (argument -s or --solution)",metavar=('CVE-ID'))

    parser.add_argument("-s","--solution", help="Text file with a solution to a specific vulnerability")

    parser.add_argument("-d","--delete_cve",help="Removes a vulnerability from the database",metavar=('CVE-ID'))

    parser.add_argument("-g","--generate_report",help="Generates the report with all the vulnerabilities previosly registred",metavar=('REPORT_NAME'))

    #Another options

    parser.add_argument("-o","--output", action="store_true", help="If this flag is not set, the output is the console")

    parser.add_argument("-v","--version", action="version", version="Pentshelp 1.0")

   

    args = parser.parse_args()



    if args.ports is not None:
        
        src.enumeration.detect_ports(args.ports, args.output)


    elif args.os is not None:
        
        src.enumeration.detect_os(args.os, args.output)

    elif args.directories is not None:
        
        src.enumeration.detect_directories(args.directories[0],args.directories[1],args.output)

    elif args.subdomains is not None:

        src.enumeration.detect_subdomains(args.subdomains[0],args.subdomains[1],args.output)

    elif args.add_host is not None:

        src.enumeration.add_host(args.add_host[0], args.add_host[1])

    elif args.vulnerabilities is not None:

        src.vuln_detection.detect_vulnerabilities(args.vulnerabilities, args.output)


    elif args.upload_exploit is not None:

        src.exploitation.upload_exploit(args.upload_exploit[0], args.upload_exploit[1], args.upload_exploit[2])  


    elif args.pe is not None:

        src.postexploitation.privesc(args.pe) 


    elif args.report is not None:

        src.reporting.report_cve(args.report, args.solution)


    elif args.generate_report is not None:

        src.reporting.generate_report(args.generate_report)


    elif args.delete_cve is not None:

        src.reporting.delete_cve(args.delete_cve)


    else:

        print('You must specify an option')


        
if __name__ == "__main__":

    main()
