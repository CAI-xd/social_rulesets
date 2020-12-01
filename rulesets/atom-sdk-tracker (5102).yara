/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: ATOM SDK Tracker
    Rule id: 5102
    Created at: 2018-12-05 06:36:35
    Updated at: 2020-02-21 17:48:05
    
    Rating: #0
    Total detections: 23
*/

import "androguard"

rule AtomSDKTracker
{
	meta:
		description = "All Atom SDK Apps"
	condition:
		androguard.activity("com.atom.mobilepaymentsdk.PayActivity")		
}
