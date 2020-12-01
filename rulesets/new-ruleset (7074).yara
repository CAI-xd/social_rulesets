/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ppp1
    Rule name: New Ruleset
    Rule id: 7074
    Created at: 2020-10-01 07:50:29
    Updated at: 2020-10-01 08:11:05
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Safetracker
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"


	condition:
		androguard.package_name(/safetracker/i)
		
}
