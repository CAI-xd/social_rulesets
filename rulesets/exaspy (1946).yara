/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: Exaspy
    Rule id: 1946
    Created at: 2016-11-03 19:18:31
    Updated at: 2016-11-03 19:23:12
    
    Rating: #0
    Total detections: 19
*/

import "androguard"

rule koodous : official
{
	meta:
		description = "Ruleset to detect Exaspy RAT"
		sample = "0b8eb5b517a5a841a888d583e0a187983c6028b92634116cfc9bf79d165ac988"

	strings:
		$a = "Sending log to the server. Title: %s Severity: %s Description: %s Module: %s"
		$b = "KEY_LICENSE"
		$c = "Failed to install app in system partition.\n"
		$d = "key_remote_jid"

	condition:
		androguard.url("http://www.exaspy.com/a.apk") or androguard.url("http://api.andr0idservices.com") or all of them
		
}
