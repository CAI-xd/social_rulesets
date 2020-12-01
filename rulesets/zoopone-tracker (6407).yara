/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: ZoopOne Tracker
    Rule id: 6407
    Created at: 2020-02-19 06:09:47
    Updated at: 2020-02-19 06:09:52
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule ZoopOneSDKTracker
{
	meta:
		description = "All Zoop One SDK Apps"
	condition:
		androguard.activity("sdk.zoop.one.offline_aadhaar.zoopActivity.ZoopConsentActivity") or
		androguard.activity("one.zoop.sdkesign.esignlib.qtActivity.QTApiActivity")
}
