'''
This file contains the primary functions used by the toolkit.

'''

import requests
import sys
import re

from json_strings import *


# Update the defined asset group that is in the scan policy
def update_asset(url, proxy, scan, asset_group, headers, cookie):
    try:
        requests.packages.urllib3.disable_warnings()
        asset = {"definedIPs":scan}
        s = requests.request('patch', url + 'asset/' + asset_group,
                    headers=headers,
                    cookies=cookie,
                    proxies=proxy,
                    verify=False,
                    json=asset)
        if s.status_code == 403:
            print "[-] Something is wrong with the asset group update. Verify that you are using an IP address and not DNS name."
            sys.exit(1)
        else:
            print "[+] Asset group successfully updated."
            asset_response = s.json()['response']['typeFields']
    except Exception, e:
        print str(e)
        sys.exit(1)


# Launch vulnerability scan
def launch_scan(url, proxy, scan_id, cookie, headers, scan_json):
    try:
        requests.packages.urllib3.disable_warnings()
        s = requests.request('post', url + 'scan/' + scan_id + '/launch',
                    headers=headers,
                    cookies=cookie,
                    proxies=proxy,
                    verify=False,
                    json=scan_json)
        scan_response = s.json()['response']
        if "Invalid" in str(scan_response):
            print "[-] Something is wrong with the scan launch."
        else:
            print "[+] Scan successfully launched."
    except Exception, e:
        print str(e)
        sys.exit(1)


# Request vulnerabilities
def pull_vulns(vulns, sev, url, cookie, headers, proxy):
    try:
        requests.packages.urllib3.disable_warnings()
        if re.match(r'[a-zA-Z]', vulns) is not None:
            query = query_json_dns(vulns, sev)
        else:
            query = query_json_ip(vulns, sev)
        s = requests.request('post', url + 'analysis',
                             headers=headers,
                             cookies=cookie,
                             proxies=proxy,
                             verify=False,
                             json=query)
        vuln_data = s.json()['response']['results']
        if sev == '4':
            print("[+]")
            print("[+] CRITICAL severity vulnerabilities for " + vulns + ":")
            print("-------------------------------------------------------------------")
        elif sev == '4,3':
            print("[+]")
            print("[+] CRITICAL and HIGH severity vulnerabilities for " + vulns + ":")
            print("-------------------------------------------------------------------")
        elif sev == '4,3,2':
            print("[+]")
            print("[+] CRITICAL, HIGH, and MEDIUM severity vulnerabilities for " + vulns + ":")
            print("-------------------------------------------------------------------")
        return vuln_data
    except Exception, e:
        print str(e)
        sys.exit(1)


def search_vulns(search_data, url, cookie, headers, proxy):
    try:
        requests.packages.urllib3.disable_warnings()
        s = requests.request('post', url + 'analysis',
                             headers=headers,
                             cookies=cookie,
                             proxies=proxy,
                             verify=False,
                             json=search_data)
        search_response = s.json()['response']['results']
        return search_response
    except Exception, e:
        print str(e)
        sys.exit(1)

