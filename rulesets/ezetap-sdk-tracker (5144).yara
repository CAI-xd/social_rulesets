/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Ezetap SDK Tracker
    Rule id: 5144
    Created at: 2018-12-13 12:06:16
    Updated at: 2018-12-13 12:07:06
    
    Rating: #0
    Total detections: 8
*/

import "androguard"

rule EzetapSDKTracker
{
	meta:
		description = "All Ezetap SDK Apps"
	condition:
		androguard.activity("com.eze.api.EzeAPIActivity")
}
