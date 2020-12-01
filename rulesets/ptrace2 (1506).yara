/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: ptrace2
    Rule id: 1506
    Created at: 2016-06-14 15:13:44
    Updated at: 2016-06-14 15:13:54
    
    Rating: #0
    Total detections: 18809
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
		$l = "ptrace"

	condition:
		any of them
		
}
