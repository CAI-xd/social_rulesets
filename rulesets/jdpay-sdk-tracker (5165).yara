/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: JDPay SDK Tracker
    Rule id: 5165
    Created at: 2018-12-24 08:01:08
    Updated at: 2018-12-24 08:01:33
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule JDPaySDKTrackerActivity
{
	meta:
		description = "All JDPay SDK Apps"
	condition:
		androguard.activity("com.justdialpayui.PaymentsActivity")
}
