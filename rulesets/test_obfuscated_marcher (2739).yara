/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: test_obfuscated_marcher
    Rule id: 2739
    Created at: 2017-05-23 03:02:55
    Updated at: 2017-05-31 18:00:29
    
    Rating: #0
    Total detections: 64
*/

import "androguard"
import "file"
import "cuckoo"


rule test_obfuscated_marcher
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$b_1 = "vi?rus"
		$b_2 = "a?v?g"
		$b_3 = "a?nt?i"
		$b_4 = "v?i?ru?s"
	
	condition:
		any of ($b_*)
		
				
}
