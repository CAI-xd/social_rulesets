/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Benow SDK Tracker
    Rule id: 5160
    Created at: 2018-12-21 11:17:46
    Updated at: 2018-12-21 11:18:16
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule BenowSDKTrackerActivity
{
	meta:
		description = "All Benow SDK Apps"
	condition:
		androguard.activity("com.benow.paymentsdk.activities.WebViewActivity")
}
