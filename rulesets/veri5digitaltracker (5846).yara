/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Veri5DigitalTracker
    Rule id: 5846
    Created at: 2019-08-18 08:40:55
    Updated at: 2019-08-18 08:42:00
    
    Rating: #0
    Total detections: 5
*/

import "androguard"

rule Veri5DigitalTracker
{
	meta:
		description = "This rule detects Veri5 Digital SDK"
	strings:
		$a = "https://sandbox.veri5digital.com/video-id-kyc/api/1.0/"
		$b = "https://prod.veri5digital.com/video-id-kyc/api/1.0/"
	condition:
		($a or $b)  and
		androguard.permission(/android.permission.INTERNET/)
}
