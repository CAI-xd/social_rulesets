/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TimoKats
    Rule name: yara ruleset 2
    Rule id: 7231
    Created at: 2020-11-10 10:07:21
    Updated at: 2020-11-10 10:10:16
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule FamilyDroidKungFu
{
	meta:
		description = "Prevents FamilyDroidKungFu from activating"  
		
	strings:
		$a = "/system/app/com.google.ssearch.apk"
		$b = "/data/app/com.allen.mp-1.apk"

	condition:
		($a or $b)
}
