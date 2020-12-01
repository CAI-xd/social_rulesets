/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Aadhaar eKYC Tracker
    Rule id: 5379
    Created at: 2019-03-29 07:22:37
    Updated at: 2019-03-29 07:24:04
    
    Rating: #0
    Total detections: 384
*/

import "androguard"

rule AadhaareKYCTracker
{
	meta:
		description = "This rule detects potential Aadhaar eKYC apps"
	strings:
		$a = "Aadhaar"
		$b = "eKYC"
		$c = "eSign"		
	condition:
		(($a) and ($b or $c)) and
		androguard.permission(/android.permission.INTERNET/)
}
