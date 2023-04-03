# SIEM Content

## Description

## Required tools

* Clone [detection-rules](https://github.com/elastic/detection-rules) repo with specify version
```
git clone -b 8.5 https://github.com/elastic/detection-rules.git
```
or clone master branch and change versions in "detection_rules\etc\packages.yml" file.</br>
* Add .detection-rules-cfg.json file to repo:
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
* Modify _post_dict_conversion() func in "detection_rules\rule.py" file (comment 925 string):
```
    def _post_dict_conversion(self, obj: dict) -> dict:
        """Transform the converted API in place before sending to Kibana."""
		...
        self._convert_add_related_integrations(obj)
        #self._convert_add_required_fields(obj)
        self._convert_add_setup(obj)
		...
``` 
* Modify bulk_create() func to
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

* Modify non-schema fields in file non-ecs-schema.json:
```
		...
		"ObjectType": "keyword",
		"NewValue": "keyword",
		"NewValueType": "keyword",
		...
```

### Commands
```
python -m detection_rules validate-rule <rule_path>
python -m detection_rules kibana upload-rule -f <rule_path> -r
python -m detection_rules kibana upload-rule -d <rules_dir> -r - to recursively upload rules to kibana
```


## Tactics

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
	    <td rowspan="9"><a href="https://attack.mitre.org/techniques/T1547/">Boot or Logon Autostart Execution</a></td>
	    <td rowspan="9"><a href="https://attack.mitre.org/techniques/T1547/001/">Registry Run Keys / Startup Folder</a></td>
	    <td>[Custom] Create persistence: Registry Run Keys (based on process activity)</td>
		<td>[-]</td>
		<td> [-] req add, Set-ItemProperty</td>
	</tr>
	<!-- #2 -->
	<tr>
	    <td>[Custom] Create persistence: Registry Run Keys (based on registry activity)</td>
		<td>Windows_Autorun_Modification</td>
		<td>[+] WinEventLog 4657 + SACL, Sysmon 13 + XML</td>	
	</tr>
	<!-- #3 -->
	<tr>
	    <td>[Custom] Use persistence: Start process using RunOnce</td>
		<td>[Custom] Start_process_using_RunOnce</td>
		<td>[+] runonce.exe -> TargetProcess (WinEventLog 4688, Sysmon 1)</td>
	</tr>
	<!-- #4 -->
	<tr>
	    <td>[Custom] Use persistence: Start process as RunOnceEx</td>
		<td>[Custom] Start_process_using_RunOnceEx</td>
		<td>[+] runonce.exe -> rundll32.exe -> TargetProcess (WinEventLog 4688, Sysmon 1)</td>
	</tr>
	<!-- #5 -->
	<tr>
	    <td>[Custom] Create persistence: Create file in StartupFolder</td>
		<td>Windows_Autorun_Modification</td>
		<td>[+] WinEventLog 4663 + SACL, Sysmon 11 + XML</td>
	</tr>
	<!-- #6 -->
	<tr>
	    <td>[Custom] Create persistence: Modidy StartupFolder</td>
		<td>Modify_StartupFolder</td>
		<td>[-] WinEventLog 4657 + SACL, Sysmon 13 + XML</td>
	</tr>
	<!-- #7 -->
	<tr>
	    <td>[Custom] Use persistence: Start process from StartupFolder</td>
		<td>[Custom] Start_process_from_StartupFolder</td>
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
	<!-- #1 -->
	<tr>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1037/">Boot or Logon Initialization Scripts</a></td>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1037/001/">Logon Script (Windows)</a></td>
	    <td>[Custom] Create persistance: Logon Script (Windows)</td>
		<td>Userinitmprlogonscript_Modify</td>
		<td></td>
	</tr>
	<tr>
	    <td>[Custom] Use persistance: Start process as Logon Script (Windows)</td>
		<td>[Custom] Start_process_as_Logon_Script</td>
		<td>Terminal Services</td>
	</tr>
</table>