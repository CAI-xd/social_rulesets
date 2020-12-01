/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: secauvr2
    Rule name: android rat sign
    Rule id: 5287
    Created at: 2019-02-18 16:41:49
    Updated at: 2019-02-18 16:42:18
    
    Rating: #0
    Total detections: 3
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "possible variant of rat android"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "5af6cfde"
		$b = "Y29tLmFuZHJvaWQuc2V0dGluZ3M6c3RyaW5nL3llcw=="

	condition:
		$a or $b
		
}
