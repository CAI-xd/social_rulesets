/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: JusPay Tracker
    Rule id: 4994
    Created at: 2018-10-18 02:18:01
    Updated at: 2018-12-14 12:19:23
    
    Rating: #0
    Total detections: 298
*/

import "androguard"

rule JusPayActivity
{
	meta:
		description = "All JusPay SDK Apps"
	condition:
		androguard.activity("in.juspay.godel.PaymentActivity")	or
		androguard.activity("in.juspay.juspaysafe.LegacyPaymentActivity")

}
