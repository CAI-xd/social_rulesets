/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: PPP
    Rule id: 1499
    Created at: 2016-06-13 11:49:46
    Updated at: 2016-06-13 11:50:52
    
    Rating: #0
    Total detections: 36
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
		$l = "PPP begin"
		$k = "PPP end"
		$m = "PPP Error"

	condition:
		any of them
		
}
