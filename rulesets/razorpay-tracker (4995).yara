/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: RazorPay Tracker
    Rule id: 4995
    Created at: 2018-10-18 04:03:24
    Updated at: 2018-12-13 08:17:56
    
    Rating: #2
    Total detections: 781
*/

import "androguard"

rule RazorPayActivity
{
	meta:
		description = "All RazorPay SDK Apps"
	condition:
		androguard.activity("com.razorpay.CheckoutActivity")		
}
