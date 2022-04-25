import argparse
import src.enumeration
import src.vuln_detection


def main():

    parser = argparse.ArgumentParser(prog="pentshelp", description="Semi-automatic pentesting tool which speeds up many common tasks related to this technique")

    #Enumeration options

    parser.add_argument("-p","--ports", help="Shows open ports on the selected target")

    parser.add_argument("--os", help="Shows the operating system of the selected target")

    parser.add_argument("--directories", help="Shows the directories of the select target (web server)", nargs=2)

    parser.add_argument("--subdomains", help="Shows the subdomains of the select target (web server)", nargs=2)

    parser.add_argument("-a","--add_host",help="Adds hostname to /etc/hosts", nargs=2)


    #Vulnerabilities detection options

    parser.add_argument("--vulnerabilities",help="Detect possible vulnerabilities on the selected target")


    #Another options

    parser.add_argument("-o","--output", help="If none file is specified, the output is the console")

    parser.add_argument("-v","--version", action="version", version="Pentshelp 1.0")

   

    args = parser.parse_args()



    #Parsing enumeration options

    if args.ports is not None:
        
        src.enumeration.detect_ports(args.ports, args.output)


    elif args.os is not None:
        
        src.enumeration.detect_os(args.os, args.output)

    elif args.directories is not None:
        
        src.enumeration.detect_directories(args.directories[0],args.directories[1],args.output)

    elif args.subdomains is not None:

        src.enumeration.detect_subdomains(args.subdomains[0],args.directories[1],args.output)

    elif args.add_host is not None:

        src.enumeration.add_host(args.add_host[0], args.add_host[1])

    elif args.vulnerabilities is not None: #TODO

        src.vuln_detection.detect_vulnerabilities(args.vulnerabilities[0], args.output)












    else:

        print('You must specify an option')


        







if __name__ == "__main__":

    main()

