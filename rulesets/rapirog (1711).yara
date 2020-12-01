/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: rapirog
    Rule id: 1711
    Created at: 2016-08-01 11:52:52
    Updated at: 2016-08-03 15:45:52
    
    Rating: #0
    Total detections: 92
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
		$a = "com.loki.sdk.ILokiListene"

	condition:
		any of them
		
}
