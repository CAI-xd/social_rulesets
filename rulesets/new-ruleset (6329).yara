/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dana
    Rule name: New Ruleset
    Rule id: 6329
    Created at: 2020-01-29 20:47:21
    Updated at: 2020-02-05 20:33:29
    
    Rating: #0
    Total detections: 592
*/

import "androguard"


rule DANA_disruptive_adds
{
	meta:
		author = "Dana Kalujny"
		description = "This rule is dedicated to find apps with the code pattern: onBackPressed or doubleBackToExitPressedOnce"
		date = "1.2.2020"
		
	strings:
		$patternA = "onBackPressed"
		$patternB = "doubleBackToExitPressedOnce"

	condition:
		$patternA or $patternB and
		androguard.url("https://play.google.com/store/apps")
				
}
