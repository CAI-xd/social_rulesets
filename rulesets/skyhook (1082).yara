/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: SkyHook
    Rule id: 1082
    Created at: 2015-12-20 18:48:15
    Updated at: 2015-12-23 07:29:35
    
    Rating: #0
    Total detections: 388
*/

import "androguard"
import "file"
import "cuckoo"


rule skyhook : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	$a = "_sdka"
	$b = "_sdkab"
	$c = "_sdkzf"
	$d = "_sdkyc"
	condition:
		all of them
		
}
