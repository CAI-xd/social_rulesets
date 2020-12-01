/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: ZaakPay Tracker
    Rule id: 5175
    Created at: 2019-01-01 17:50:29
    Updated at: 2019-01-01 17:51:37
    
    Rating: #0
    Total detections: 31
*/

import "androguard"

rule ZaakPayTracker
{
	meta:
		description = "This rule detects ZaakPay gateway powered apps"
	strings:
		$a = "https://api.zaakpay.com/zaakpay.js"
		$b = "https://api.zaakpay.com/"
	condition:
		($a or $b) and
		androguard.permission(/android.permission.INTERNET/)		
}
