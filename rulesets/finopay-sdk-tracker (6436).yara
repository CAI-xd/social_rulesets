/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: FinoPay SDK Tracker
    Rule id: 6436
    Created at: 2020-03-03 11:15:31
    Updated at: 2020-03-03 11:16:30
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule FinoPaySDKTrackerActivity
{
	meta:
		description = "All Fino SDK Apps"
	condition:
		androguard.activity("com.finopaytech.finosdk.activity.DeviceSettingActivity") or
		androguard.activity("com.finopaytech.finosdk.fragments.BTDiscoveryFragment") or
		androguard.activity("com.finopaytech.finosdk.activity.MainTransactionActivity") or
		androguard.activity("com.finopaytech.finosdk.activity.TransactionStatusActivity")
}
