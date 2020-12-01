/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: EBS Payments SDK Tracker
    Rule id: 5104
    Created at: 2018-12-05 06:58:06
    Updated at: 2018-12-13 08:22:59
    
    Rating: #0
    Total detections: 14
*/

import "androguard"

rule EBSPaymentsSDKActivity
{
	meta:
		description = "All EBS Payments SDK Apps"
	condition:
		androguard.activity("com.ebs.android.sdk.PaymentDetailActivity")		
}
