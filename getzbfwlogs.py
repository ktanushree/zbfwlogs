#!/usr/bin/env python
"""
CGNX script to download ZBFW logs into a CSV

tanushree@cloudgenix.com

"""
import cloudgenix
import pandas as pd
import os
import sys
import yaml
from netaddr import IPAddress, IPNetwork
from random import *
import argparse
import logging
import datetime


# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Get ZBFW Logs'


# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # will get caught below.
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None

appid_appname = {}
siteid_sitename = {}
sitename_siteid = {}
elemid_elemname = {}
zoneid_zonename = {}
policyid_policyname = {}
ruleid_rulename = {}
spidrulename_ruleid = {}
siteid_policyid = {}
policyid_rulenameslist = {}
policyid_ruleidlist = {}

def createdicts(cgx_session):
    print("\tApp Defs")
    resp = cgx_session.get.appdefs()
    if resp.cgx_status:
        appdefs = resp.cgx_content.get("items", None)

        for app in appdefs:
            appid_appname[app['id']] = app['display_name']

    else:
        print("ERR: Could not query appdefs")
        cloudgenix.jd_detailed(resp)

    print("\tSites")
    resp = cgx_session.get.sites()
    if resp.cgx_status:
        sitelist = resp.cgx_content.get("items", None)

        for site in sitelist:
            siteid_sitename[site['id']] = site['name']
            sitename_siteid[site['name']] = site['id']
            siteid_policyid[site['id']] = site['security_policyset_id']
    else:
        print("ERR: Could not query sites")
        cloudgenix.jd_detailed(resp)

    print("\tElements")
    resp = cgx_session.get.elements()
    if resp.cgx_status:
        elemlist = resp.cgx_content.get("items", None)

        for elem in elemlist:
            elemid_elemname[elem['id']] = elem['name']
    else:
        print("ERR: Could not query elements")
        cloudgenix.jd_detailed(resp)

    print("\tSecurity Zones")
    resp = cgx_session.get.securityzones()
    if resp.cgx_status:
        zonelist = resp.cgx_content.get("items", None)

        for zone in zonelist:
            zoneid_zonename[zone['id']] = zone['name']
    else:
        print("ERR: Could not query zones")
        cloudgenix.jd_detailed(resp)

    print("\tSecurity Policy Sets")
    resp = cgx_session.get.securitypolicysets()
    if resp.cgx_status:
        policylist = resp.cgx_content.get("items", None)

        for policy in policylist:
            policyid_policyname[policy['id']] = policy['name']

    else:
        print("ERR: Could not query security policy sets")
        cloudgenix.jd_detailed(resp)

    print("\tSecurity Policy Rules")
    for spid in policyid_policyname.keys():
        resp = cgx_session.get.securitypolicyrules(securitypolicyset_id=spid)
        if resp.cgx_status:
            rulelist = resp.cgx_content.get("items", None)

            rulenames = []
            ruleids = []
            for rule in rulelist:
                ruleid_rulename[rule['id']] = rule['name']
                rulenames.append(rule['name'])
                ruleids.append(rule['id'])
                spidrulename_ruleid[(spid, rule['name'])] = rule['id']

            policyid_rulenameslist[spid] = rulenames
            policyid_ruleidlist[spid] = ruleids

        else:
            print("ERR: Could not query security policy rules for securitypolicy set {}".format(
                policyid_policyname[spid]))
            cloudgenix.jd_detailed(resp)

    return


def getappname(x):
    if x in appid_appname.keys():
        return appid_appname[x]
    else:
        return x


def getzone(x):
    if x in zoneid_zonename.keys():
        return zoneid_zonename[x]
    else:
        return x


def getzonelist(zonelist):
    zonestr = ""
    for x in zonelist:
        if x in zoneid_zonename.keys():
            zonestr = zonestr + "{},".format(zoneid_zonename[x])
        else:
            zonestr = zonestr + "{},".format(x)

    return zonestr[:-1]


def getsecuritypolicy(x):
    if x in policyid_policyname.keys():
        return policyid_policyname[x]
    else:
        return x


def getrule(x):
    if x in ruleid_rulename.keys():
        return ruleid_rulename[x]
    else:
        return x


def getrulelist(rulelist):
    rulestr = ""
    for x in rulelist:
        if x in ruleid_rulename.keys():
            rulestr = rulestr + "{},".format(ruleid_rulename[x])
        else:
            rulestr = rulestr + "{},".format(x)

    return rulestr[:-1]


def getelement(x):
    if x in elemid_elemname.keys():
        return elemid_elemname[x]
    else:
        return x


def getapplist(applist):
    appstr = ""
    for i in applist:
        if i in appid_appname.keys():
            appname = appid_appname[i]
        else:
            appname = "unknown"

        if appname in appstr:
            continue
        else:
            appstr = appstr + "{},".format(appname)

    return appstr[:-1]


def gettime(x):
    utctime = datetime.datetime.fromtimestamp(int(x) / 1000).strftime('%Y-%m-%d %H:%M:%S')
    return utctime


def getaction(actionlist):
    actionstr = ""
    for x in actionlist:
        actionstr = actionstr + "{},".format(x)

    return actionstr[:-1]


def getdirection(x):
    if x:
        return "LAN > WAN"
    else:
        return "WAN > LAN"


protocol_dict = {1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 17: "UDP"}


def getprotocol(x):
    if x in protocol_dict.keys():
        return protocol_dict[x]
    else:
        return x



def getzbfwlogs(cgx_session, siteid, ruleidlist, action, starttime, endtime):
    print("INFO: Getting ZBFW logs...")
    start_time_iso = starttime.isoformat() + "Z"
    end_time_iso = endtime.isoformat() + "Z"

    if action == "any":
        data = {
            "start_time": start_time_iso,
            "end_time": end_time_iso,
            "debug_level": "all",
            "filter": {
                "security_policy_rule": ruleidlist,
                "site": [siteid]
            }
        }

    else:
        data = {
            "start_time": start_time_iso,
            "end_time": end_time_iso,
            "debug_level": "all",
            "filter": {
                "security_policy_rule": ruleidlist,
                "security_policy_rule_action": action,
                "site": [siteid]
            }
        }

    resp = cgx_session.post.flows_monitor(data=data, api_version="v3.5")
    zbfwrules = pd.DataFrame()
    if resp.cgx_status:
        flowdata = resp.cgx_content.get("flows", None)

        flows = flowdata.get("items", None)

        for flow in flows:
            security_policy_rules = flow.get("security_policy_rules", None)
            rulesdf = pd.DataFrame(security_policy_rules)

            sourcezones = list(rulesdf.security_source_zone_id.unique())
            destzones = list(rulesdf.security_destination_zone_id.unique())
            actions = list(rulesdf.security_policy_rule_action.unique())
            rules = list(rulesdf.security_policy_rule_id.unique())

            zbfwrules = zbfwrules.append({"element_id": flow["element_id"],
                                          "source_ip": flow["source_ip"],
                                          "source_port": flow["source_port"],
                                          "destination_ip": flow["destination_ip"],
                                          "destination_port": flow["destination_port"],
                                          "protocol": flow["protocol"],
                                          "app_id": flow["app_id"],
                                          "app_list": flow["sec_fc_app_id"],
                                          "flow_start_time_ms": flow["flow_start_time_ms"],
                                          "flow_end_time_ms": flow["flow_end_time_ms"],
                                          "bytes": flow["bytes_c2s"] + flow["bytes_s2c"],
                                          "security_destination_zone_id": destzones,
                                          "security_source_zone_id": sourcezones,
                                          "security_policy_rule_id": rules,
                                          "actionlist": actions,
                                          "protocol_num": flow["protocol"],
                                          "lan_to_wan": flow["lan_to_wan"]
                                          }, ignore_index=True)

    else:
        print("ERR: Could not retrieve flow records")
        cloudgenix.jd_detailed(resp)

    return zbfwrules


def cleanexit(cgx_session):
    print("Logging Out")
    cgx_session.get.logout()
    sys.exit()


def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default="https://api.elcapitan.cloudgenix.com")

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-P", help="Use this Password instead of prompting",
                             default=None)

    # Commandline for entering ZBFW specific info
    zbfw_group = parser.add_argument_group('ZBFW Rule specific information',
                                           'Information shared here will be used to filter flows to extract ZBFW logs')
    zbfw_group.add_argument("--sitename", "-S", help="Name of the Site", default=None)
    zbfw_group.add_argument("--rulename", "-R", help="Rule Name", default="ALL")
    zbfw_group.add_argument("--action", "-A", help="Action. Allowed values: any, allow, deny, reject", default="any")
    zbfw_group.add_argument("--starttime", "-ST", help="Start time in format YYYY-MM-DDTHH:MM:SSZ", default=None)
    zbfw_group.add_argument("--endtime", "-ET", help="Start time in format YYYY-MM-DDTHH:MM:SSZ", default=None)


    args = vars(parser.parse_args())

    sitename = args["sitename"]
    if sitename is None:
        print("ERR: Sitename is required")
        sys.exit()

    rulename = args["rulename"]
    if rulename == "ALL":
        print("INFO: No rule specified. Logs from all the rules will be queried")

    action = args["action"]
    if action not in ["any", "allow", "deny", "reject"]:
        print("ERR: Invalid action: {}. Please choose from: any, allow, deny, reject".format(action))
        sys.exit()

    starttime = args["starttime"]
    endtime = args["endtime"]
    stime = None
    etime = None
    if starttime is None or endtime is None:
        print("ERR: For time range, please provide both starttime and endtime in format YYYY-MM-DDTHH:MM:SSZ")
        sys.exit()

    else:
        if "." in starttime:
            stime = datetime.datetime.strptime(starttime, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            stime = datetime.datetime.strptime(starttime, "%Y-%m-%dT%H:%M:%SZ")

        if "." in endtime:
            etime = datetime.datetime.strptime(endtime, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            etime = datetime.datetime.strptime(endtime, "%Y-%m-%dT%H:%M:%SZ")

    ############################################################################
    # Instantiate API & Login
    ############################################################################

    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # Build Translation Dicts
    ############################################################################
    print("INFO: Building translation dictionaries")
    createdicts(cgx_session)

    ############################################################################
    # Validate filtering data
    # Get ZBFW Logs
    ############################################################################
    if sitename in sitename_siteid.keys():
        sid = sitename_siteid[sitename]

        if sid in siteid_policyid.keys():
            policyid = siteid_policyid[sid]

            if policyid in policyid_rulenameslist.keys():
                rules = policyid_rulenameslist[policyid]

                rulelist = []
                if rulename == "ALL":
                    rulelist = policyid_ruleidlist[policyid]

                else:
                    if rulename in rules:
                        rulelist = [spidrulename_ruleid[policyid, rulename]]

                    else:
                        print("ERR: Rule {} not found in Security Policy Set {} attached to Site {}".format(rulename, policyid_policyname[policyid], sitename))
                        print("Please pick from: {}".format(policyid_rulenameslist[policyid]))
                        cleanexit(cgx_session)

                zbfwlogs = getzbfwlogs(cgx_session, sid, rulelist, action, stime, etime)

                if len(zbfwlogs) > 0:
                    zbfwlogs["app_name"] = zbfwlogs["app_id"].apply(getappname)
                    zbfwlogs["element_name"] = zbfwlogs["element_id"].apply(getelement)
                    zbfwlogs["security_rule"] = zbfwlogs["security_policy_rule_id"].apply(getrulelist)
                    zbfwlogs["source_zone"] = zbfwlogs["security_source_zone_id"].apply(getzonelist)
                    zbfwlogs["destination_zone"] = zbfwlogs["security_destination_zone_id"].apply(getzonelist)
                    zbfwlogs["applications"] = zbfwlogs["app_list"].apply(getapplist)
                    zbfwlogs["start_time"] = zbfwlogs["flow_start_time_ms"].apply(gettime)
                    zbfwlogs["end_time"] = zbfwlogs["flow_end_time_ms"].apply(gettime)
                    zbfwlogs["action"] = zbfwlogs["actionlist"].apply(getaction)
                    zbfwlogs["site_name"] = sitename
                    zbfwlogs["direction"] = zbfwlogs["lan_to_wan"].apply(getdirection)
                    zbfwlogs["protocol"] = zbfwlogs["protocol_num"].apply(getprotocol)

                    ############################################################################
                    # Write to CSV
                    ############################################################################
                    # get time now.
                    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

                    # create file-system friendly tenant str.
                    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()

                    # Set filenames
                    filename = os.path.join('./', '%s_zbfwlogs_%s.csv' % (tenant_str, curtime_str))
                    print("INFO: Logs Downloaded. Saving to file {}".format(filename))
                    zbfwlogs.to_csv(filename, index=False,
                                     columns=["site_name", "element_name", "source_ip", "source_port",
                                              "destination_ip", "destination_port", "protocol", "applications",
                                              "action", "direction", "security_rule", "source_zone", "destination_zone",
                                              "bytes", "start_time", "end_time"])

                else:
                    print("INFO: No ZBFW logs found! Filer Used:\nSite:{}\nRules:{}\nAction:{}\nStart Time: {}\nEnd Time: {}".format(sitename,rulename,action,starttime,endtime))




            else:
                print("ERR: Could not process Security Policy Set {}".format(policyid_policyname[policyid]))
                cleanexit(cgx_session)




        else:
            print("ERR: Security Policy Set not configured on site {}".format(sitename))
            cleanexit(cgx_session)

    else:
        print("ERR: Site {} not found. Please reenter sitename".format(sitename))
        cleanexit(cgx_session)

    ############################################################################
    # Logout to clear session.
    ############################################################################
    cgx_session.get.logout()

    print("Logging Out")
    sys.exit()

if __name__ == "__main__":
    go()
