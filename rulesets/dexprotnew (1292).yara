/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Dexprotnew
    Rule id: 1292
    Created at: 2016-03-15 09:12:28
    Updated at: 2016-03-15 09:12:46
    
    Rating: #0
    Total detections: 3608
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
		$l = "dp.arm-v8.so.dat"

	condition:
		any of them
		
}
