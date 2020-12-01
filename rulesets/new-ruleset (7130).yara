/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Tuinlamp
    Rule name: New Ruleset
    Rule id: 7130
    Created at: 2020-11-03 17:19:54
    Updated at: 2020-11-08 11:40:01
    
    Rating: #1
    Total detections: 0
*/

import "androguard"


rule TractorSMS
{
	meta:
		description = "Detects tractor-apps that send and receive SMS"
	strings:
		$a = "const-string v3, u'sms_body'"
		$b = "const-string v0, u'sms_body'"
		$c = "http://10.0.0.172"

	condition:
		$a and $b and $c and androguard.app_name("com.safetest.tractor")
		
}
