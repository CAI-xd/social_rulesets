/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: FingPay Tracker
    Rule id: 5151
    Created at: 2018-12-15 04:31:54
    Updated at: 2019-01-01 05:23:10
    
    Rating: #0
    Total detections: 1
*/

import "androguard"

rule FingPayActivity
{
	meta:
		description = "All FingPay SDK Apps"
	strings:
		$a = "https://fingpayap.tapits.in/fpaepsservice/"
	condition:
		($a) or
		androguard.activity("com.tapits.fingpay.FingerPrintScreen")
		

}
