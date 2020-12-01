/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Freecharge SDK Tracker
    Rule id: 5134
    Created at: 2018-12-12 07:20:46
    Updated at: 2018-12-13 08:14:01
    
    Rating: #0
    Total detections: 18
*/

import "androguard"

rule FreechargeINSDKActivity
{
	meta:
		description = "All Freecharge India Apps"
	condition:
		androguard.activity("in.freecharge.checkout.android.pay.PayInitActivity")
}
