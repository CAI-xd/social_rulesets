/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Wibmo SDK Tracker
    Rule id: 5120
    Created at: 2018-12-09 13:29:55
    Updated at: 2018-12-09 13:30:17
    
    Rating: #0
    Total detections: 29
*/

import "androguard"

rule WibmoSDKTrackerActivity
{
	meta:
		description = "All Wibmo SDK Apps"
	condition:
		androguard.activity("com.enstage.wibmo.sdk.inapp.InAppInitActivity")
}
