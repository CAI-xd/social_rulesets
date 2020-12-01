/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: sandoja
    Rule name: New Ruleset
    Rule id: 2784
    Created at: 2017-05-26 19:14:32
    Updated at: 2017-05-27 21:16:17
    
    Rating: #0
    Total detections: 114
*/

import "androguard"



rule slempo : package
{
	meta:
		description = "This rule detects the slempo (slembunk) variant malwares by using package name and app name comparison"
		sample = "24c95bbafaccc6faa3813e9b7f28facba7445d64a9aa759d0a1f87aa252e8345"

	condition:
		androguard.package_name("org.slempo.service")
		}
