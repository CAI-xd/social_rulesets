/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: PanosR
    Rule name: test5
    Rule id: 3691
    Created at: 2017-09-28 10:59:01
    Updated at: 2017-09-28 11:00:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"



	condition:
		androguard.activity("*.jifenActivity") or

		androguard.activity("*.JFMain")

		
}
