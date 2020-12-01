/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: CashFree SDK Tracker
    Rule id: 6423
    Created at: 2020-02-26 12:39:28
    Updated at: 2020-02-26 12:39:31
    
    Rating: #0
    Total detections: 7
*/

import "androguard"

rule CashFreeSDKTracker
{
	meta:
		description = "All CashFree SDK Apps"
	condition:
		( androguard.activity("com.gocashfree.cashfreesdk.CFPaymentActivity") or
		androguard.activity("com.gocashfree.cashfreesdk.CFUPIPaymentActivity") or
		androguard.activity("com.gocashfree.cashfreesdk.AmazonPayActivity") or
		androguard.activity("com.gocashfree.cashfreesdk.GooglePayActivity") or
		androguard.activity("com.gocashfree.cashfreesdk.CFPhonePayActivity"))
}
