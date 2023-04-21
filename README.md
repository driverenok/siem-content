# SIEM Content

SIEM Content is repo that contain detection rules for Elastic SIEM

## Table of Contents

 - [SIEM Content](#siem-content)
   - [Overview of this repository](#overview-of-this-repository)
   - [Credits tools](#credits-tools)
   - [Getting started](#getting-started)
     - [Get Sysmon Base Config](#get-sysmon-base-config)
	 - [Get Merge-SysmonXml.ps1](#get-merge-sysmonxml.ps1-powershell-module)
	 - [Detection Rules](#detection-rules)
	 - [Detection Rules Commands](#detection-rules-commands)
   - [Rules](#rules)
	 
## Overview of this repository

| Folder                                    |  Description                                                     |
|------------------------------------------ |----------------------------------------------------------------- |
| [`audit/sysmon/`](audit/sysmon)           | Contain a Sysmon configuration                                   |
| [`audit/wineventlog/`](audit/wineventlog) | Containing tools to customise Windows Event Logging              |
| [`elastic-rules/`](elastic-rules)         | Directory where rules are stored                                 |
| [`samples/`](samples)                     | This is a container events samples associated to specific attack |

## Credit tools

 - [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) - Sysmon base config file.
 - [sysmon-modular](https://github.com/olafhartong/sysmon-modular) - Credit a Merge-SysmonXml.ps1 to merge base and custom Sysmon confif file.
 - [detection-rules](https://github.com/elastic/detection-rules) - Push rules to Kibana SIEM/

## Getting started

### Get Sysmon Base Config

Clone [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config.git) repo
```
git clone https://github.com/SwiftOnSecurity/sysmon-config.git
```

Copy sysmonconfig-export.xml file to "siem-content\audit\sysmon":
```
copy ..\sysmon\sysmonconfig-export.xml siem-content\audit\sysmon\
```

### Get Merge-SysmonXml.ps1 powershell module 

Clone [sysmon-modular](https://github.com/olafhartong/sysmon-modular.git) repo:
```
git clone https://github.com/olafhartong/sysmon-modular.git
```

Copy Merge-SysmonXml.ps1 file to "siem-content\audit\sysmon" and 
```
>Import-Module .\Merge-SysmonXml.ps1

   //**                  ***//
  ///#(**               **%(///
  ((&&&**               **&&&((
   (&&&**   ,(((((((.   **&&&(
   ((&&**(((((//(((((((/**&&((      _____                                                            __      __
    (&&///((////(((((((///&&(      / ___/__  ___________ ___  ____  ____        ____ ___  ____  ____/ /_  __/ /___ ______
     &////(/////(((((/(////&       \__ \/ / / / ___/ __ `__ \/ __ \/ __ \______/ __ `__ \/ __ \/ __  / / / / / __ `/ ___/
     ((//  /////(/////  /(((      ___/ / /_/ (__  ) / / / / / /_/ / / / /_____/ / / / / / /_/ / /_/ / /_/ / / /_/ / /
    &(((((#.///////// #(((((&    /____/\__, /____/_/ /_/ /_/\____/_/ /_/     /_/ /_/ /_/\____/\__,_/\__,_/_/\__,_/_/
     &&&&((#///////((#((&&&&          /____/
       &&&&(#/***//(#(&&&&
         &&&&****///&&&&                                                                            by Olaf Hartong
            (&    ,&.
             .*&&*.
			 
>dir

    Directory: .\siem-content\audit\sysmon

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        07.04.2023     14:29           3139 custom_sysmon_config.xml
-a----        07.03.2023     16:53          37134 Merge-SysmonXml.ps1
-a----        06.12.2022     22:19         123257 sysmon_config-SwiftOnSecurity.xml

>Merge-AllSysmonXml -Path ( Get-ChildItem '*.xml') -AsString | Out-File sysmonconfig.xml
```

### Detection Rules

Clone [detection-rules](https://github.com/elastic/detection-rules) repo with specify version
```
git clone -b 8.5 https://github.com/elastic/detection-rules.git
```
or clone master branch and change versions in "detection_rules\etc\packages.yml" file.</br>

Add .detection-rules-cfg.json file to repo:
```
{
"elastic_search_url": "",
"kibana_url": "",
"cloud_id": "",
"elasticsearch_username": "",
"elasticsearch_password": "",
"kibana_username": "",
"kibana_password": ""
}
```

Modify _post_dict_conversion() func in "detection_rules\rule.py" file (comment 925 string):
```
def _post_dict_conversion(self, obj: dict) -> dict:
    """Transform the converted API in place before sending to Kibana."""
	...
    self._convert_add_related_integrations(obj)
    #self._convert_add_required_fields(obj)
    self._convert_add_setup(obj)
	...
``` 

* Modify bulk_create() func in "kibana\resources.py" file to:
```
@classmethod
def bulk_create(cls, resources: list):
    for r in resources:
        assert isinstance(r, cls)

    responses = Kibana.current().post(cls.BASE_URI + "/_bulk_create", data=resources)
        
    if "error" in responses[0]:
        if responses[0]["error"]["status_code"] == 409:
            responses = Kibana.current().put(cls.BASE_URI + "/_bulk_update", data=resources)
    return [cls(r) for r in responses]
```
This is necessary for updating existing if SIEM rule.

Modify non-schema fields in file "detection_rules\etc\non-ecs-schema.json":
```
{
...
"ObjectType": "keyword",
"NewValue": "keyword",
"NewValueType": "keyword",
...
}
```

### Detection Rules Commands
```
python -m detection_rules validate-rule <rule_path>
python -m detection_rules kibana upload-rule -f <rule_path> -r
python -m detection_rules kibana upload-rule -d <rules_dir> -r - to recursively upload rules to kibana
```


## Rules

### [Persistence](https://attack.mitre.org/tactics/TA0003/) 

#### [Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)

| Technique   | Elastic SIEM                                                                                                                                             | Other SIEM                                                                  | Note                                               |
|------------ |--------------------------------------------------------------------------------------------------------------------------------------------------------- |---------------------------------------------------------------------------- | -------------------------------------------------- |
| Screensaver | [CUSTOM_Create_persistance_Modify_Screensaver.toml](./elastic-rules/windows/Persistence/CUSTOM_Create_persistance_Modify_Screensaver.toml)               |[PT] Windows_Screensaver_modification, Create_persistance_Modify_Screensaver | WinEventLog: EID 4657 + SACL, Sysmon: EID 13 + XML |
|             | [CUSTOM_Use_persistance_Start_process_as_Screensaver.toml](./elastic-rules/windows/Persistence/CUSTOM_Use_persistance_Start_process_as_Screensaver.toml) | Use_persistance_Start_Process_as_Screensaver                                | WinEventLog: EID 4688, Sysmon: EID 1 + XML         |

#### [Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)

| Technique                                                                            | Elastic SIEM                                                                                                                                                                                                 | Other SIEM                                       | Note                                               |
|------------------------------------------------------------------------------------- |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |------------------------------------------------- | -------------------------------------------------- |
| [Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) | CUSTOM_Create_persistence_Registry_Run_Keys_based_on_command_activity.toml                                                                                                                                   |                                                  | reg add, powershell, wmi                           |
                                                                                      | [CUSTOM_Create_persistence_Registry_Run_Keys_based_on_registry_activity.toml](./elastic-rules/windows/Persistence/CUSTOM_Create_persistence_Registry_Run_Keys_based_on_registry_activity.toml)               | [PT] Windows_Autorun_Modification                | WinEventLog: EID 4657 + SACL, Sysmon: EID 13 + XML |
                                                                                      | [CUSTOM_Create_persistence_Hidden_Registry_Run_Keys_based_on_registry_activity.toml](./elastic-rules/windows/Persistence/CUSTOM_Create_persistence_Hidden_Registry_Run_Keys_based_on_registry_activity.toml) |                                                  | WinEventLog: EID 4657 + SACL, Sysmon: EID 13 + XML |
                                                                                      | [CUSTOM_Use_persistence_Start_process_as_RunOnce.toml](./elastic-rules/windows/Persistence/CUSTOM_Use_persistence_Start_process_as_RunOnce.toml)                                                             | Use_persistence_Start_process_using_RunOnce      | WinEventLog: EID 4688, Sysmon: EID 1 + XML         |
                                                                                      | [CUSTOM_Use_persistence_Start_process_as_RunOnceEx.toml](./elastic-rules/windows/Persistence/CUSTOM_Use_persistence_Start_process_as_RunOnceEx.toml)                                                         | Use_persistence_Start_process_using_RunOnceEx    | WinEventLog: EID 4688, Sysmon: EID 1 + XML         |
|                                                                                      | [CUSTOM_Use_persistence_Start_process_from_StartupFolder.toml](./elastic-rules/windows/Persistence/CUSTOM_Use_persistence_Start_process_from_StartupFolder.toml)                                             | Use_persistance_Start_process_from_StartupFolder | WinEventLog: EID 4688, Sysmon: EID 1 + XML         |
|                                                                                      | [CUSTOM_Use_persistence_Start_process_as_Run_mechanism_based_ShellCore_engine.toml](./elastic-rules/windows/Persistence/CUSTOM_Use_persistence_Start_process_as_Run_mechanism_based_ShellCore_engine.toml)   |                                                  | WinEventLog: EID 9707 Microsoft-Windows-Shell-Core |                             |
|                                                                                      | [CUSTOM_Create_persistence_Modify_StartupFolder.toml](./elastic-rules/windows/Persistence/CUSTOM_Create_persistence_Modify_StartupFolder.toml)                                                               | Create_persistance_Modify_StartupFolder          | WinEventLog: EID 4657 + SACL, Sysmon: EID 13 + XML |
|                                                                                      | [CUSTOM_Create_persistence_Create_file_in_StartupFolder.toml](./elastic-rules/windows/Persistence/CUSTOM_Create_persistence_Create_file_in_StartupFolder.toml)                                               |                                                  | WinEventLog: EID 4663 + SACL, Sysmon: EID 11 + XML |
| [Shortcut Modification](https://attack.mitre.org/techniques/T1547/009/)              | [CUSTOM_Create_persistence_Shortcut_Modification.toml](./elastic-rules/windows/Persistence/CUSTOM_Create_persistence_Shortcut_Modification.toml)                                                             | Create_persistance_Shortcut_Modification         | WinEventLog: EID 4663 + SACL for LNK files         |

#### [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)

| Technique                                                               | Elastic SIEM                                                                                                                                                               | Other SIEM                                    | Note                                               |
|------------------------------------------------------------------------ |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |---------------------------------------------- | -------------------------------------------------- |
|[Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/) | [CUSTOM_Create_persistance_Logon_Script_Windows.toml](./elastic-rules/windows/Persistence/CUSTOM_Create_persistance_Logon_Script_Windows.toml)                             | [PT] Userinitmprlogonscript_Modify            | WinEventLog: EID 4657 + SACL, Sysmon: EID 13 + XML |
|                                                                         | [CUSTOM_Use_persistance_Start_process_as_Logon_Script_Windows.toml](./elastic-rules/windows/Persistence/CUSTOM_Use_persistance_Start_process_as_Logon_Script_Windows.toml) | Use_persistance_Start_process_as_Logon_Script | WinEventLog: EID 4688, Sysmon: EID 1 + XML         |

#### [Create or Modify System Process ](https://attack.mitre.org/techniques/T1543/)

| Technique                                                               | Elastic SIEM                                                                                                                                                                   | Other SIEM                   | Note                                               |
|------------------------------------------------------------------------ |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |----------------------------- | -------------------------------------------------- |
|[Windows Service](https://attack.mitre.org/techniques/T1543/003/)        | [CUSTOM_Create_persistence_DNSAdmins_based_on_registry_activity.toml](./elastic-rules/windows/Persistence/CUSTOM_Create_persistence_DNSAdmins_based_on_registry_activity.toml) | Create_persistance_DNSAdmins | WinEventLog: EID 4657 + SACL, Sysmon: EID 13 + XML |
|                                                                         | [CUSTOM_Create_persistence_DNSAdmins_based_on_cmd_activity.toml](./elastic-rules/windows/Persistence/CUSTOM_Create_persistence_DNSAdmins_based_on_cmd_activity.toml)           | Create_persistance_DNSAdmins | WinEventLog: EID 4688, Sysmon: EID 1 + XML         |
