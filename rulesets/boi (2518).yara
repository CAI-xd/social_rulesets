/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TSOTIXFORCE
    Rule name: BOI
    Rule id: 2518
    Created at: 2017-04-21 13:43:38
    Updated at: 2017-08-18 12:22:29
    
    Rating: #0
    Total detections: 212
*/

import "androguard"
import "file"
import "cuckoo"


rule BOI
{
	meta:
		description = "This rule detects the BOI applications, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$l = "com.bankofireland.mobilebanking"
		$m = "com.boi.tablet365"

	condition:
		any of them
		
}
