/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Citrus SDK Tracker
    Rule id: 5142
    Created at: 2018-12-13 11:50:27
    Updated at: 2018-12-13 11:51:04
    
    Rating: #0
    Total detections: 25
*/

import "androguard"

rule CitrusSDKActivity
{
	meta:
		description = "All Citrus SDK Apps"
	condition:
		androguard.activity("com.citrus.sdk.CitrusActivity")
}
