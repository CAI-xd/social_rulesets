/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Leegality eSign eNACH SDK Tracker
    Rule id: 5123
    Created at: 2018-12-09 16:08:11
    Updated at: 2018-12-09 16:13:11
    
    Rating: #0
    Total detections: 1
*/

import "androguard"

rule LeegalitySDKTracker
{
	meta:
		description = "All Leegality SDK Apps"
	condition:
		androguard.activity("com.leegality.leegality.Leegality")
}
