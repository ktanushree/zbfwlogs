# CloudGenix Download ZBFW Logs
This script is used to download ZBFW logs.

#### Synopsis
This script enables users to download ZBFW logs for a specified time period. The users have to provide a sitename. Filters such as rulename, action, starttime and endtime can also be used to fine tune the results.

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.4.3b1 - <https://github.com/CloudGenix/sdk-python>
    * CloudGenix ID-Name Utility >= 2.0.1 - <https://github.com/ebob9/cloudgenix-idname>
* ProgressBar2

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `getzbfwlogs.py`. 

#### Usage:
Download all ZBFW logs:
```
./getzbfwlogs.py -S Sitename -A any -R ALL -ST "2020-10-23T00:00:00Z" -ET "2020-10-23T01:00:00Z"
```
Download ZBFW logs for a specific action. Allowed values are: any, allow, deny, reject:
```
./getzbfwlogs.py -S Sitename -A allow -R ALL -ST "2020-10-23T00:00:00Z" -ET "2020-10-23T01:00:00Z"
```

Download ZBFW logs for a specific rule:
```
./getzbfwlogs.py -S Sitename -A allow -R "Permit-Corp-Out" -ST "2020-10-23T00:00:00Z" -ET "2020-10-23T01:00:00Z"
```

#### Help Text:
```
usage: getzbfwlogs.py [-h] [--controller CONTROLLER] [--email EMAIL]
                      [--pass PASS] [--sitename SITENAME]
                      [--rulename RULENAME] [--action ACTION]
                      [--starttime STARTTIME] [--endtime ENDTIME]

CloudGenix: Get ZBFW Logs.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod:
                        https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting

ZBFW Rule specific information:
  Information shared here will be used to filter flows to extract ZBFW logs

  --sitename SITENAME, -S SITENAME
                        Name of the Site
  --rulename RULENAME, -R RULENAME
                        Rule Name
  --action ACTION, -A ACTION
                        Action. Allowed values: any, allow, deny, reject
  --starttime STARTTIME, -ST STARTTIME
                        Start time in format YYYY-MM-DDTHH:MM:SSZ
  --endtime ENDTIME, -ET ENDTIME
                        Start time in format YYYY-MM-DDTHH:MM:SSZ
                        
```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional CloudGenix Documentation at <http://support.cloudgenix.com>
