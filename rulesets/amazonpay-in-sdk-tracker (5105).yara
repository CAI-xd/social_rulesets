/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: AmazonPay IN SDK Tracker
    Rule id: 5105
    Created at: 2018-12-05 09:33:07
    Updated at: 2018-12-13 08:14:08
    
    Rating: #0
    Total detections: 44
*/

import "androguard"

rule AmazonPayINSDKActivity
{
	meta:
		description = "All Amazon Pay India Apps"
	condition:
		androguard.activity("amazonpay.silentpay.APayActivity")
}
