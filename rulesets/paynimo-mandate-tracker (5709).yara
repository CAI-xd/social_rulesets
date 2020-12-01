/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: PayNimo Mandate Tracker
    Rule id: 5709
    Created at: 2019-07-10 08:28:40
    Updated at: 2019-07-10 08:29:09
    
    Rating: #0
    Total detections: 1
*/

import "androguard"

rule PayNimoMandateActivity
{
	meta:
		description = "All PayNimo Mandate Activity Tracker"
	condition:
		androguard.activity("com.paynimo.android.payment.DigitalMandateActivity")
}
