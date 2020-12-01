/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: CreditVidya Tracker
    Rule id: 5146
    Created at: 2018-12-13 12:58:27
    Updated at: 2019-03-04 11:37:11
    
    Rating: #0
    Total detections: 8
*/

import "androguard"

rule CreditVidyaTracker
{
	meta:
		description = "This rule detects CreditVidya SDK"
	strings:
		$a = "https://api.creditvidya.com"
		$b = "https://api.creditvidya.com/sdk/api/"
		$c = "https://api.creditvidya.com/sdk/api/token/v3"		
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)
}
