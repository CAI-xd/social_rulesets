/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Digio eSign SDK
    Rule id: 5119
    Created at: 2018-12-09 13:14:25
    Updated at: 2019-03-21 13:00:32
    
    Rating: #0
    Total detections: 12
*/

import "androguard"

rule DigioESignSDKTrackerActivity
{
	meta:
		description = "All Digio eSign SDK Apps"
	strings:
		$a = "https://ext.digio.in"
	condition:
		($a or
		androguard.activity("com.digio.in.esign2sdk.DigioEsignActivity"))
}
