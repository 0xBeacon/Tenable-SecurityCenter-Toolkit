
'''
This is the settings file to define variables used by the toolkit.



'''
import base64

# Security Center Credentials
user = ''   # <----Set This
pwd = ''    # <----Set This


# Optional method to base64 clear text password
# Note that this is not secure and only keeps it from someone looking over your shoulder (and even that's questionable)
# Create by doing - "echo -ne 'password' | base64"
# pwd = base64.b64decode('VGhpc2lzeW91cnBhc3N3b3JkaW5iYXNlNjRlbmNvZGluZw==')

# Set the FQDN for your Security Center system
securitycenter_fqdn = ''    # <----Set This

# Set the Asset Group
asset_group = 'API_Scan_Asset_Group'    # <----Set This

# Set the scan ID and name
scan_id = '100'    # <----Set This
scan_name = 'API_AUTOMATION'    # <----Set This


# Debug and proxy settings.  Allows for MiTM SecurityCenter calls for troubleshooting.
# Examples: Burp or Fiddler.  Viewing JSON data is typically much easier with Fiddler.
debug = 0
if debug == 1:
    proxy = {
        "http": "http://127.0.0.1:8080",
        "https": "https://127.0.0.1:8080",
        }
else:
    proxy = {
        "http": "",
        "https": ""
        }

# Set Security Center API url
url = "https://" + securitycenter_fqdn + "/rest/"

