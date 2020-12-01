/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Quagga SDK Tracker
    Rule id: 5145
    Created at: 2018-12-13 12:54:39
    Updated at: 2020-02-19 03:47:23
    
    Rating: #0
    Total detections: 1
*/

import "androguard"

rule QuaggaSDKTrackerActivity
{
	meta:
		description = "All Quagga SDK Apps"
	condition:
		androguard.activity("quagga.com.sdk.ConsentActivity") or
		androguard.activity("com.aadhaarapi.sdk.gateway_lib.qtActivity.AadhaarAPIActivity")
}
