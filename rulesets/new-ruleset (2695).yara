/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 2695
    Created at: 2017-05-16 11:38:51
    Updated at: 2017-05-16 11:42:22
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule simplerule
{
	meta:
		description = "This rule detects a SMS Fraud malware"

	condition:
		androguard.package_name("com.hsgame.")
		
}
