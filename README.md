# SIEM Content

## Description

## Required tools
1. Clone [detection-rules](https://github.com/elastic/detection-rules) repo with specify version
```
git clone -b 8.5 https://github.com/elastic/detection-rules.git
```
or clone master branch and change versions in "detection_rules\etc\packages.yml" file.</br>
2. Add .detection-rules-cfg.json file to repo:
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
3. Modify _post_dict_conversion() func in "detection_rules\rule.py" file (comment 925 string):
```
    def _post_dict_conversion(self, obj: dict) -> dict:
        """Transform the converted API in place before sending to Kibana."""
		...
        self._convert_add_related_integrations(obj)
        #self._convert_add_required_fields(obj)
        self._convert_add_setup(obj)
		...
``` 
4. Modify bulk_create() func to
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
	<tr>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1547/">Boot or Logon Autostart Execution</a></td>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1547/001/">Registry Run Keys</a></td>
	    <td>[Custom] Create persistence: Registry Run Keys</td>
		<td>Windows_Autorun_Modification</td>
		<td></>
	</tr>
	<tr>
	    <td></td>
		<td></td>
		<td></td>
	</tr>
		<tr>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1547/">Boot or Logon Autostart Execution</a></td>
	    <td rowspan="2"><a href="https://attack.mitre.org/techniques/T1547/001/">Startup Folder</a></td>
	    <td>[Custom] Create persistence: Registry Run Keys</td>
		<td>Windows_Autorun_Modification</td>
		<td></>
	</tr>
	<tr>
	    <td></td>
		<td></td>
		<td></td>
	</tr>
	<tr>
		<td></td>
		<td></td>
		<td></td>
		<td></td>
		<td></td>
	</tr>
</table>