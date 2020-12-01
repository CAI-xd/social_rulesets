/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: RuPay Tracker
    Rule id: 5143
    Created at: 2018-12-13 11:58:57
    Updated at: 2018-12-13 12:05:03
    
    Rating: #0
    Total detections: 239
*/

import "androguard"

rule RuPayTracker
{
	meta:
		description = "This rule detects RuPay merchant verification"
	strings:
		$a = "https://swasrec.npci.org.in"
		$b = "https://swasrec2.npci.org.in"
		$c = "https://mwsrec.npci.org.in/MWS/Scripts/MerchantScript_v1.0.js"
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)
}
