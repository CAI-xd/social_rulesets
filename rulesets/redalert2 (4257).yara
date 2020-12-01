/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: roach
    Rule name: RedAlert2
    Rule id: 4257
    Created at: 2018-03-07 08:39:39
    Updated at: 2018-08-19 21:47:57
    
    Rating: #0
    Total detections: 56
*/

import "androguard"

rule redalert2
{
	meta:
		author = "R"
		description = "https://clientsidedetection.com/new_android_trojan_targeting_over_60_banks_and_social_apps.html"

	strings:
		$intent = "HANDLE_COMMANDS"

	condition:
		$intent
}
