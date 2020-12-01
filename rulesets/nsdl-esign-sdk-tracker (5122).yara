/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: NSDL eSign SDK Tracker
    Rule id: 5122
    Created at: 2018-12-09 15:04:32
    Updated at: 2018-12-17 07:48:42
    
    Rating: #0
    Total detections: 4
*/

import "androguard"

rule NSDLESignSDKTrackerActivity
{
	meta:
		description = "All NSDL eSign SDK Apps"
	condition:
		androguard.activity("com.nsdl.egov.esignaar.NsdlEsignActivity")
}
