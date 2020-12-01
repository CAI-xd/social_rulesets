/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_adb_port
    Rule id: 4160
    Created at: 2018-02-05 06:09:44
    Updated at: 2018-02-05 06:10:22
    
    Rating: #0
    Total detections: 1542
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "service.adb.tcp.port"

	condition:
		$a	
}
