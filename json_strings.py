'''
Functions that set various JSON strings used to communicate with SecurityCenter.

'''

def scan_json(scan_id, scanname):
    json = {
        "id": scan_id,
        "name": scanname,
        "description": "",
        "context": "",
        "status": 0,
        "createdTime": "",
        "modifiedTime": "",
        "group": {
            "id": 0,
            "name": "Administrator"},
        "groups": [],
        "tags": "",
        "repository": {},
        "schedule": {
            "start": "TZID=:Invalid dateInvalid date",
            "repeatRule": "FREQ=TEMPLATE;INTERVAL=",
            "type": "template"},
        "dhcpTracking": "false",
        "emailOnLaunch": "true",
        "emailOnFinish": "true",
        "type": "policy",
        "policy": {
            "id": "1000001"},
        "plugin": {
            "id": -1,
            "name": "",
            "description": ""},
        "zone": {
            "id": -1},
        "timeoutAction": "rollover",
        "rolloverType": "template",
        "scanningVirtualHosts": "false",
        "classifyMitigatedAge": 0,
        "assets": [],
        "ipList": "",
        "maxScanTime": "unlimited"
    }
    return json


def query_json_dns(vulns, sev):
    query = {
        "query": {
            "name": "",
            "description": "",
            "context": "analysis",
            "status": -1,
            "createdTime": 0,
            "modifiedTime": 0,
            "groups": [],
            "tags": "",
            "type": "vuln",
            "tool": "sumid",
            "sourceType": "cumulative",
            "startOffset": 0,
            "endOffset": 50,
            "filters": [{
                "id": "dnsName",
                "filterName": "dnsName",
                "operator": "=",
                "type": "vuln",
                "isPredefined": "true",
                "value": vulns},
                {
                    "id": "severity",
                    "filterName": "severity",
                    "operator": "=",
                    "type": "vuln",
                    "isPredefined": "true",
                    "value": sev
                }],
            "sortColumn": "severity",
            "sortDirection": "desc"},
        "sourceType": "cumulative",
        "sortField": "severity",
        "sortDir": "desc",
        "type": "vuln"
    }
    return query

def query_json_ip(vulns, sev):
    query = {
        "query":{
            "name":"",
            "description":"",
            "context":"analysis",
            "status":-1,
            "createdTime":0,
            "modifiedTime":0,
            "groups":[],
            "tags":"",
            "type":"vuln",
            "tool":"vulndetails",
            "sourceType":"cumulative",
            "startOffset":0,
            "endOffset":50,
            "filters":[{
                "id":"ip",
                "filterName":"ip",
                "operator":"=",
                "type":"vuln",
                "isPredefined":True,
                "value":vulns},
                {
                    "id":"severity",
                    "filterName":"severity",
                    "operator":"=",
                    "type":"vuln",
                    "isPredefined":True,
                    "value":sev}],
            "vulnTool":"vulndetails"},
        "sourceType":"cumulative",
        "type":"vuln"
    }
    return query


def search_json(search_data):
    find_json = {
        "query": {
            "name": "",
            "description": "",
            "context": "analysis",
            "status": -1,
            "createdTime": 0,
            "modifiedTime": 0,
            "groups": [],
            "tags": "",
            "type": "vuln",
            "tool": "listvuln",
            "sourceType": "cumulative",
            "startOffset": 0,
            "endOffset": 50,
            "filters": [{
                "id": "pluginName",
                "filterName": "pluginName",
                "operator": "=",
                "type": "vuln",
                "isPredefined": "true",
                "value": search_data},
                {"id": "severity",
                 "filterName": "severity",
                 "operator": "=",
                 "type": "vuln",
                 "isPredefined": "true",
                 "value": "1,2,3,4"}],
            "vulnTool": "listvuln"},
        "sourceType": "cumulative",
        "type": "vuln"}
    return find_json

