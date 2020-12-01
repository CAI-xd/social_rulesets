/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Yasin
    Rule name: New Ruleset
    Rule id: 7174
    Created at: 2020-11-08 23:52:28
    Updated at: 2020-11-09 16:38:07
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule BadNews : official
{
	meta:
		description = "This rule detects BadNews malware, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	    $a = "AlarmManager"
		$b = "broadcast"
		$c = "primaryServerUrl"

	condition:
		androguard.package_name("com.mobidisplay.advertsv1") and
		androguard.permission(/android.permission.INTERNET/) and
		$a and
		$b and
		$c
		

		
}
