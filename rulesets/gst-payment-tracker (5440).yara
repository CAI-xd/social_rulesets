/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: GST Payment Tracker
    Rule id: 5440
    Created at: 2019-04-10 10:08:43
    Updated at: 2019-04-10 10:12:43
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule GSTPaymentTracker
{
	meta:
		description = "This rule detects All apps with GST Payment link"
	strings:
		$a = "https://payment.gst.gov.in/payment/"
		$b = "https://payment.gst.gov.in/payment/trackpayment"
	condition:
		($a or $b) and
		androguard.permission(/android.permission.INTERNET/)
}
