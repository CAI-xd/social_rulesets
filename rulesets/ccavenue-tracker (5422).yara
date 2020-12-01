/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: CCAvenue Tracker
    Rule id: 5422
    Created at: 2019-04-08 08:03:18
    Updated at: 2019-04-08 08:04:00
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule CCAvenueTracker
{
	meta:
		description = "All CCAvenue SDK Apps"
	condition:
		androguard.activity("com.ccavenue.indiasdk.PayOptionsActivity")		
}
