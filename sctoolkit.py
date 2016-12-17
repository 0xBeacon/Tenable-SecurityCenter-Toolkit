#!/usr/bin/python
'''
Main SecurityCenter Toolkit program.

Verify settings.py variables are set prior to running.

'''

__version__ = '0.0.5'
__author__ = '@thatchriseckert'

import sys
import base64
import argparse
import re

try:
    import requests
except Exception, e:
    print("[-] Module import failure. Verify all necessary packages are installed.")
    print("[-] Error: " + str(e))
    sys.exit(0)

from settings import *
from json_strings import *
from tenable_data import *
from menus import *

# Test settings.py
#---------------------------------------------------------------
settings_verify = all([user, pwd, securitycenter_fqdn])
if settings_verify == False:
    print("[-] Please set variables in settings.py before running.")
    sys.exit(1)

# Set HTTP Headers
headers = {'Content-type': 'application/json'}

# Grab Authentication Token
def grab_token(user, pwd, url, headers, proxy):
    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.request('post', url + 'token',
                    json={'username': user, 'password': pwd},
                    headers=headers,
                    proxies=proxy,
                    verify=False)
        global cookie
        cookie = dict(TNS_SESSIONID=(r.cookies['TNS_SESSIONID']))
        token = r.json()['response']['token']
        tokenized_header = {'X-SecurityCenter': str(token)}
        headers.update(tokenized_header)
        if token == None:
            print "[-] Something is wrong with grabbing an authentication token."
            sys.exit(1)
        else:
            print "[+] Auth token successfully grabbed."
    except Exception, e:
        print str(e)
        sys.exit(1)



# Main Logic
#------------------------------------------------------------------
def main():
    #
    # -----------------------------------------------------------------
    # Define Parser Options
    parser = argparse.ArgumentParser(description="Remove -h for better help menu.")
    parser.add_argument('-s', '--scan', type=str, required=False)
    parser.add_argument('-v', '--vulns', type=str, required=False)
    parser.add_argument('-c', '--crit', type=str, required=False)
    parser.add_argument('-f', '--find', type=str, required=False)
    args = parser.parse_args()
    scan = args.scan
    vulns = args.vulns
    crit = args.crit
    search_data = args.find

    # Misc Definitions
    dict_list = []
    titles = ['DNS', 'IP', 'PluginID', 'Severity', 'Vulnerability']
    scan_json_data = scan_json(scan_id, scan_name)

    # Go
    if scan == None and vulns == None and search_data == None:
        print(
        bcolors.FAIL + "[-] Either scan, vuln, or find arguments are required.  Enjoy this lovely help menu and try again...\n" + bcolors.ENDC)
        usage(__version__)
    elif scan is not None:
        print "-------------------------------------------------------"
        print (bcolors.OKBLUE + "[*] Entering Scan Kick-Off Mode" + bcolors.ENDC)
        print "-------------------------------------------------------"
        scan_settings_verify = all([asset_group, scan_id])
        if scan_settings_verify == False:
            print("[-] Please set the asset_group and scan_id variables in settings.py before running.")
            sys.exit(1)
        else:
            grab_token(user, pwd, url, headers, proxy)
            update_asset(url, proxy, scan, asset_group, headers, cookie)
            launch_scan(url, proxy, scan_id, cookie, headers, scan_json_data)
            print "\n"
    elif vulns is not None:
        print"-------------------------------------------------------"
        print(bcolors.OKGREEN + "[*] Entering Host Vulnerability Pull Mode" + bcolors.ENDC)
        print "-------------------------------------------------------"
        if crit == None:
            sev = '4'
            if vulns is not None:
                print"[+] No -c option, selecting critical only."
        elif crit == "critical":
            sev = '4'
        elif crit == "high":
            sev = '4,3'
        elif crit == "medium":
            sev = '4,3,2,'
        elif crit == "all":
            sev = '4,3,2,1'
        else:
            print"[-] You've provided an incorrect option for -c.  Defaulting to critical severity only.\n"
            sev = '4'
        grab_token(user, pwd, url, headers, proxy)
        vuln_response = pull_vulns(vulns, sev, url, cookie, headers, proxy)
        vuln_formatting(dict_list, vuln_response)
        table = format_as_table(dict_list, titles, titles, sort_by_key='DNS', sort_order_reverse=False)
        print(table)

    elif search_data is not None:
        print"-------------------------------------------------------"
        print(bcolors.HEADER + "[*] Entering Search Mode" + bcolors.ENDC)
        print "-------------------------------------------------------"
        grab_token(user, pwd, url, headers, proxy)
        find_json = search_json(search_data)
        search_response = search_vulns(find_json, url, cookie, headers, proxy)
        vuln_formatting(dict_list, search_response)
        table = format_as_table(dict_list, titles, titles, sort_by_key='DNS', sort_order_reverse=False)
        print(table)

    else:
        print(bcolors.FAIL + "[-] Debug: Triggered else in main()" + bcolors.ENDC)
        sys.exit(1)


if __name__ == "__main__":
    main()


