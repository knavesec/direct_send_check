import dns.resolver
import argparse
import socket


def lookup_ms_dns(domain, verbose):
    formatted_domain = domain.replace('.', '-')
    res = dns.resolver.Resolver()
    res.nameservers = ['8.8.8.8']
    try:
        result = res.resolve('{}.mail.protection.outlook.com'.format(formatted_domain), 'A')
        if verbose:
            for ipval in result:
                print('IP', ipval.to_text())
        return True
    except:
        if verbose:
            print("MS Outlook Records do not exist")
        return False

def check_smtp_external(domain, verbose):
    formatted_domain = domain.replace('.', '-')

    target = socket.gethostbyname("{}.mail.protection.outlook.com".format(formatted_domain))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((target,25))
        if result ==0:
            if verbose:
                print("Port {} on host {} is open".format(25, "{}.mail.protection.outlook.com".format(formatted_domain)))
            return True
        s.close()
        return False
    except socket.gaierror:
        if verbose:
            print("MS Direct Send host not resolving")
        return False
    except socket.error:
        if verbose:
            print("MS Direct Send Server not responding")
        return False

def check_direct_send(args):

    ms_dns = lookup_ms_dns(args.domain, args.verbose)
    smtp_ext = False
    if ms_dns:
        smtp_ext = check_smtp_external(args.domain, args.verbose)

    if (ms_dns and smtp_ext):
        print("[+] Domain {} might be vulnerable to MS Direct Send spoofing".format(args.domain))
    else:
        print("[-] Domain {} likely is not vulnerable to MS Direct Send spoofing".format(args.domain))

def main():
    parser = argparse.ArgumentParser(description="Potential MS Direct Send Check")
    parser.add_argument("-d","--domain",required=True,help="Domain to check")
    parser.add_argument("-v","--verbose",required=False, default=False, action="store_true", help="Enable verbose messages")

    args = parser.parse_args()
    check_direct_send(args)



main()