/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: TrustEVTracker
    Rule id: 5622
    Created at: 2019-06-17 14:13:04
    Updated at: 2019-06-17 14:13:06
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule TrustEVTracker
{
	meta:
		description = "This rule detects TransUnion TrustEV SDK"
	strings:
		$a = "https://app.trustev.com/api/v2.0/session"
	condition:
		$a  and
		androguard.permission(/android.permission.INTERNET/)
}
