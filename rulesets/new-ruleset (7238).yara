/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Tuinlamp
    Rule name: New Ruleset
    Rule id: 7238
    Created at: 2020-11-10 10:22:07
    Updated at: 2020-11-10 10:22:51
    
    Rating: #0
    Total detections: 0
*/

rule SaveMeProtection
{
meta: 
description = "Protect against the harmful SaveMe application"

strings: 
	$a = "http://xxxxmarketing.com"
	$b = "GTSTSR.EXT_SMS"

condition:
	($a and $b)
}
