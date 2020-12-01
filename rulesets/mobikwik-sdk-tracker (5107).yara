/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Mobikwik SDK Tracker
    Rule id: 5107
    Created at: 2018-12-05 09:44:15
    Updated at: 2018-12-13 08:14:19
    
    Rating: #0
    Total detections: 12
*/

import "androguard"

rule MobikwikSDKActivity
{
	meta:
		description = "All Mobikwik SDK Apps"
	condition:
		androguard.activity("com.mobikwik.sdk.PaymentActivity")
}
