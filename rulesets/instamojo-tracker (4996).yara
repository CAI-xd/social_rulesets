/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Instamojo Tracker
    Rule id: 4996
    Created at: 2018-10-18 07:34:49
    Updated at: 2018-12-13 08:16:46
    
    Rating: #0
    Total detections: 118
*/

import "androguard"

rule InstamojoActivity
{
	meta:
		description = "All Instamojo SDK Apps"
	condition:
		androguard.activity("com.instamojo.android.activities.PaymentActivity")
}
