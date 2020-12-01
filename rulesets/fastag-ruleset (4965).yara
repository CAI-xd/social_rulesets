/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: FASTag Ruleset
    Rule id: 4965
    Created at: 2018-10-10 12:39:43
    Updated at: 2018-12-13 08:15:22
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule netc_detect
{
	meta:
		description = "This rule detects FASTag apps"
	strings:
		$a = "http://npci.org/etc/schema"
	condition:
		($a) and
		androguard.permission(/android.permission.INTERNET/)		
}
