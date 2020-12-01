/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Paynimo SDK Tracker
    Rule id: 5130
    Created at: 2018-12-11 11:12:31
    Updated at: 2019-01-11 11:00:27
    
    Rating: #0
    Total detections: 23
*/

import "androguard"

rule PayNimoActivity
{
	meta:
		description = "All PayNimo SDK Apps"
	condition:
		androguard.activity("com.paynimo.android.payment.PaymentActivity")
}
