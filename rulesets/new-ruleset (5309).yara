/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: DAY0222
    Rule name: New Ruleset
    Rule id: 5309
    Created at: 2019-02-24 09:01:55
    Updated at: 2019-02-25 01:53:22
    
    Rating: #0
    Total detections: 21
*/

import "androguard"

rule testwahaha2
{
	condition:
		androguard.url("https://www.google.com.hk/")
}
