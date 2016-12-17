# Tenable SecurityCenter Toolkit

This tool was built to assist with day to day administration tasks that would be too slow to do within the web interface.  Primarily tested from OSX.

## Features:
- Launch a scan against a host, and have the results emailed once completed.
- Quick output of vulnerabilities known to a host.
- Search through known vulnerabilities and output affected hosts.

## Planned For Future Releases:
- Output hosts vulnerable to specific PluginID.
- Output vulnerability details.

---
## Initial Setup
You must first set a few things within SecurityCenter for this to work, as well as collect a few pieces of information to enter into the settings file.

- Create a vulnerability scan job to be used by script.
- Create a static IP asset group to be used as the scan target.
- Set up the report to be emailed.  
