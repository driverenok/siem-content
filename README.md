# SIEM Content

SIEM Content is repo that contain detection rules for Elastic SIEM

## Table of Contents

 - [SIEM Content](#siem-content)
   - [Overview of this repository](#overview-of-this-repository)
   - [Credits tools](#credits-tools)
   - [Getting started](#getting-started)
     - [Get Sysmon Base Config](#get-sysmon-base-config)
	 - [Get Merge-SysmonXml.ps1](#get-merge-sysmonxml.ps1)
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

## Credits tools

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
		...
		"ObjectType": "keyword",
		"NewValue": "keyword",
		"NewValueType": "keyword",
		...
```

### Detection Rules Commands
```
python -m detection_rules validate-rule <rule_path>
python -m detection_rules kibana upload-rule -f <rule_path> -r
python -m detection_rules kibana upload-rule -d <rules_dir> -r - to recursively upload rules to kibana
```


## Rules

### [Persistence](https://attack.mitre.org/tactics/TA0003/) 

<table>
	<tr>
	    <th>Techniques</th>
	    <th>Sub-techniques</th>
	    <th>Elastic SIEM</th>
		<th>Other SIEM</th>
		<th>Note</th>
	</tr>
	<!-- #1 -->
	<tr>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1546/">Event Triggered Execution </a></td>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1546/002/">Screensaver</a></td>
	    <td>[Custom] Create persistance: Modify Screensaver</td>
		<td>[PT] Windows_Screensaver_modification, Create_persistance_Modify_Screensaver</td>
		<td>[+] WinEventLog 4657 + SACL, Sysmon 13 + XML</td>
	</tr>
	<!-- #2 -->
	<tr>
	    <td>[Custom] Use persistance: Start process as Screensaver</td>
		<td>Use_persistance_Start_Process_as_Screensaver</td>
		<td>[+] WinEventLog 4688, Sysmon 1</td>
	</tr>	
	<!-- #1 -->
	<tr>
	    <td rowspan="11"><a href="https://attack.mitre.org/techniques/T1547/">Boot or Logon Autostart Execution</a></td>
	    <td rowspan="10"><a href="https://attack.mitre.org/techniques/T1547/001/">Registry Run Keys / Startup Folder</a></td>
	    <td>[Custom] Create persistence: Registry Run Keys (based on process activity)</td>
		<td>[-]</td>
		<td> [-] req add, Set-ItemProperty</td>
	</tr>
	<!-- #2 -->
	<tr>
	    <td><a href="./elastic-rules/windows/Persistence/[Custom]_Create_persistence_Registry_Run_Keys_based_on_registry_activity.toml">[Custom] Create persistence: Registry Run Keys (based on registry activity)</a></td>
		<td>[PT] Windows_Autorun_Modification</td>
		<td>[+] WinEventLog 4657 + SACL, Sysmon 13 + XML</td>	
	</tr>
	<!-- #3 -->
	<tr>
	    <td><a href="./elastic-rules/windows/Persistence/[Custom]_Use_persistence_Start_process_as_RunOnce.toml">[Custom] Use persistence: Start process using RunOnce</a></td>
		<td><a href="./ptseim-rules/correlation-rules/windows/Persistence/Use_persistence_Start_process_using_RunOnce">Use_persistence_Start_process_using_RunOnce</a></td>
		<td>[+] runonce.exe -> TargetProcess (WinEventLog 4688, Sysmon 1)</td>
	</tr>
	<!-- #4 -->
	<tr>
	    <td><a href="./elastic-rules/windows/Persistence/[Custom]_Use_persistence_Start_process_as_RunOnceEx.toml">[Custom] Use persistence: Start process as RunOnceEx</a></td>
		<td><a href="./ptseim-rules/correlation-rules/windows/Persistence/Use_persistence_Start_process_using_RunOnceEx">Use_persistence_Start_process_using_RunOnceEx</a></td>
		<td>[+] runonce.exe -> rundll32.exe -> TargetProcess (WinEventLog 4688, Sysmon 1)</td>
	</tr>
	<!-- #5 -->
	<tr>
	    <td><a href="./elastic-rules/windows/Persistence/[Custom]_Create_persistence_Create_file_in_StartupFolder.toml">[Custom] Create persistence: Create file in StartupFolder</a></td>
		<td>[PT] Windows_Autorun_Modification</td>
		<td>[+] WinEventLog 4663 + SACL, Sysmon 11 + XML</td>
	</tr>
	<!-- #6 -->
	<tr>
	    <td><a href="./siem-content/elastic-rules/windows/Persistence/[Custom]_Create_persistence_Modify_StartupFolder.toml"">[Custom] Create persistence: Modidy StartupFolder</a></td>
		<td><a href="./ptseim-rules/correlation-rules/windows/Persistence/Create_persistance_Modify_StartupFolder">Create_Persistence_Modify_StartupFolder</a></td>
		<td>[-] WinEventLog 4657 + SACL, Sysmon 13 + XML</td>
	</tr>
	<!-- #7 -->
	<tr>
	    <td><a href="./elastic-rules/windows/Persistence/[Custom]_Use_persistence_Start_process_from_StartupFolder.toml">[Custom] Use persistence: Start process from StartupFolder</a></td>
		<td><a href="./ptseim-rules/correlation-rules/windows/Persistence/Use_persistance_Start_process_from_StartupFolder">Use_persistence_Start_process_from_StartupFolder</a></td>
		<td>[-] WinEventLog 4688, Sysmon 1 + XML</td>
	</tr>
	<!-- #8 -->
	<tr>
	    <td></td>
		<td></td>
		<td>RunServices (Once, Ex)</td>
	</tr>
	<!-- #9 -->
	<tr>
	    <td></td>
		<td></td>
		<td>Terminal Services</td>
	</tr>
	<!-- #10 -->
	<tr>
	    <td>[Custom] Use persistence: Start process as Run mechanism (based ShellCore engine)</td>
		<td>not norm for 9705-9708</td>
		<td>Based on EID 9707 (Microsoft-Windows-Shell-Core)</td>
	</tr>
	<!-- #11 -->
	<tr>
		<td><a href="https://attack.mitre.org/techniques/T1547/009/">Shortcut Modification </a></td>
	    <td>[Custom] Create persistence: Shortcut Modification</td>
		<td>Create_persistance_Shortcut_Modification</td>
		<td>WinEventLog 4663 + SACL of LNK-files</td>
	</tr>
	<!-- #1 -->
	<tr>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1037/">Boot or Logon Initialization Scripts</a></td>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1037/001/">Logon Script (Windows)</a></td>
	    <td><a href="./elastic-rules/windows/Persistence/[Custom]_Create_persistance_Logon_Script_Windows.toml">[Custom] Create persistance: Logon Script (Windows)</a></td>
		<td>[PT] Userinitmprlogonscript_Modify</td>
		<td></td>
	</tr>
	<tr>
	    <td><a href="./elastic-rules/windows/Persistence/[Custom]_Use_persistance_Start_process_as_Logon_Script_Windows.toml">[Custom] Use persistance: Start process as Logon Script (Windows)</a></td>
		<td><a href="./ptseim-rules/correlation-rules/windows/Persistence/Use_persistance_Start_process_as_Logon_Script">Use_persistence_Start_process_as_Logon_Script</a></td>
		<td></td>
	</tr>
</table>