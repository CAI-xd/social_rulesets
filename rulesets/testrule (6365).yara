/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: vilena1
    Rule name: TestRule
    Rule id: 6365
    Created at: 2020-02-07 13:09:35
    Updated at: 2020-02-07 13:43:28
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule test_rule
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a ="yywvdeuznmksaqrrgbknzgzhtycwpzcoyuzmibagol"

	condition:
		androguard.app_name("Chrome") and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED"/) and
		$a 
		
}
