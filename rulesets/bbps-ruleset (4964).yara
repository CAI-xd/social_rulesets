/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: BBPS Ruleset
    Rule id: 4964
    Created at: 2018-10-10 12:14:59
    Updated at: 2020-02-17 08:58:29
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule bbps_detect
{
	meta:
		description = "This rule detects BBPS apps"

	strings:
		$a = "http://bbps.org/schema"
		$b = "bbps/BillFetchRequest/1.0/"
		$c = "bbps/BillPaymentRequest/1.0"
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)		
}
