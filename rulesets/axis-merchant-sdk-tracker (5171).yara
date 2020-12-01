/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Axis Merchant SDK Tracker
    Rule id: 5171
    Created at: 2018-12-28 14:21:43
    Updated at: 2018-12-28 14:22:28
    
    Rating: #0
    Total detections: 19
*/

import "androguard"

rule AxisMerchantSDKActivity
{
	meta:
		description = "All Axis Merchant SDK Apps"
	condition:
		androguard.activity("com.axis.axismerchantsdk.activity.PayActivity")
}
