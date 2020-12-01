/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: PayU SDK Tracker
    Rule id: 5103
    Created at: 2018-12-05 06:50:32
    Updated at: 2018-12-13 08:14:26
    
    Rating: #0
    Total detections: 91
*/

import "androguard"

rule PayUActivity
{
	meta:
		description = "All PayU SDK Apps"
	condition:
		androguard.activity("com.payu.payuui.Activity.PayUBaseActivity")
}
