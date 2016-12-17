from operator import itemgetter

'''
This file contains menu and misc functions used by the main program.

'''



def usage(__version__):
    print("Tenable SecurityCenter 5.x API Toolkit")
    print("Version: {0}".format(__version__))
    print("Author: @thatchriseckert")
    print("Usage: sctoolkit.py <options>\n")
    print("Options:")
    print("")
    print("   *** Scan Kick-Off Mode ***")
    print("   -s, --scan <host(s)>")
    print("              Target hosts. Can be IP, multiple IPs (comma separated), or CIDR.")
    print("              ***Do not use DNS, FQDN, or hostname.  Silly asset groups can only handle one or the other.***")
    print("")
    print("   *** Search Mode ***")
    print("   -f, --find <search string>")
    print("              Searches the 'Plugin Name' field for vulnerabilities matching a string.")
    print("")
    print("   -p, --pluginid <PluginID>")
    print("              Outputs a lists of hosts vulnerable to a specific Plugin ID.")
    print("")
    print("")
    print("   *** Host Vulnerability Mode ***")
    print("   -v, --vulns <host(s)>")
    print("              Pull vulnerabilities in SC for the host specified.  Default is critical only.")
    print("              Can be IP, CIDR, or FQDN.  Note that using DNS can have hit or miss results.  IP is recommended.")
    print("")
    print("       Additional options with --vulns:")
    print("                 -c, --crit <severity>")
    print("                         critical = lists all CRITICAL severity vulnerabilities. *Default if nothing stated.")
    print("                         high = lists all CRITICAL and HIGH severity vulnerabilities.")
    print("                         medium = lists all CRITICAL, HIGH, and MEDIUM severity vulnerabilities.")
    print("                         all = lists all vulns, except informational")
    print("")
    print("                 -d, --details <PluginID>")
    print("                         This combined with --vulns will output the vulnerability details.")
    print("")
    print("Examples for --scan:")
    print("python sctoolkit.py -s 10.10.10.10")
    print("python sctoolkit.py -s '10.10.10.10, 11.11.11.11, 12.12.12.12'")
    print("python sctoolkit.py -s 10.10.10.0/24")
    print("")
    print("Examples for --find:")
    print("python sctoolkit.py -f ms16")
    print("python sctoolkit.py -f 'Oracle Java'")
    print("")
    print("Examples for --vulns:")
    print("python sctoolkit.py -v 10.10.10.10")
    print("python sctoolkit.py -v '10.10.10.10, 11.11.11.11, 12.12.12.12'")
    print("python sctoolkit.py -v 10.10.10.0/24 -c all")
    print("python sctoolkit.py -v 10.10.10.10 -c high")
    print("")


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''


def vuln_formatting(dict_list, search_response):
    for item in search_response:
        hostdns = item['dnsName'].split(".")[0]
        hostip = item['ip'] + ' '
        pluginid = item['pluginID']
        vuln_severity = item['severity']['name']
        try:
            vulnname = item['name']
        except KeyError:
            vulnname = item['pluginName']
        dict = {
            'DNS': hostdns,
            'IP': hostip,
            'PluginID': pluginid,
            'Severity': vuln_severity,
            'Vulnerability': vulnname,
        }
        dict_list.append(dict)


def format_as_table(data,
                    keys,
                    header=None,
                    sort_by_key=None,
                    sort_order_reverse=False):
    """Takes a list of dictionaries, formats the data, and returns
    the formatted data as a text table.

        Required Parameters:
            data - Data to process (list of dictionaries). (Type: List)
            keys - List of keys in the dictionary. (Type: List)

        Optional Parameters:
            header - The table header. (Type: List)
            sort_by_key - The key to sort by. (Type: String)
            sort_order_reverse - Default sort order is ascending, if
                True sort order will change to descending. (Type: Boolean)
    """
    # Sort the data if a sort key is specified (default sort order
    # is ascending)
    if sort_by_key:
        data = sorted(data,
                    key=itemgetter(sort_by_key),
                    reverse=sort_order_reverse)

        # If header is not empty, add header to data
    if header:
        # Get the length of each header and create a divider based
        # on that length
        header_divider = []
        for name in header:
            header_divider.append('-' * len(name))

        # Create a list of dictionary from the keys and the header and
        # insert it at the beginning of the list. Do the same for the
        # divider and insert below the header.
        header_divider = dict(zip(keys, header_divider))
        data.insert(0, header_divider)
        header = dict(zip(keys, header))
        data.insert(0, header)

    column_widths = []
    for key in keys:
        column_widths.append(max(len(str(column[key])) for column in data))

    # Create a tuple pair of key and the associated column width for it
    key_width_pair = zip(keys, column_widths)

    format = ('%-*s ' * len(keys)).strip() + '\n'
    formatted_data = ''
    for element in data:
        data_to_format = []
        # Create a tuple that will be used for the formatting in
        # width, value format
        for pair in key_width_pair:
            data_to_format.append(pair[1])
            data_to_format.append(element[pair[0]])
        formatted_data += format % tuple(data_to_format)
    return formatted_data