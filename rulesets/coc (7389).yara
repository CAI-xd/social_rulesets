/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: CptDerpo
    Rule name: CoC
    Rule id: 7389
    Created at: 2020-11-18 03:53:27
    Updated at: 2020-11-18 03:57:28
    
    Rating: #1
    Total detections: 0
*/

import "androguard"

rule FakeCoC
{
	meta:
		description = "This rule detects fake Clash of Clans apps"

	strings:
		$url = "cliphot.me"

	condition:
		(androguard.app_name("Clash of Clans") and androguard.permission(/SEND_SMS/)) or
		$url
		
}
