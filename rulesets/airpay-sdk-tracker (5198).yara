/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Airpay SDK Tracker
    Rule id: 5198
    Created at: 2019-01-11 11:00:36
    Updated at: 2019-01-11 11:01:03
    
    Rating: #0
    Total detections: 1
*/

import "androguard"

rule AirPaySDKActivity
{
	meta:
		description = "All AirPay SDK Apps"
	condition:
		androguard.activity("com.airpay.airpaysdk_simplifiedotp.AirpayActivity")
}
