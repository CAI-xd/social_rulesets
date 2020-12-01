/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: SignDesk eSign SDK Tracker
    Rule id: 5121
    Created at: 2018-12-09 14:53:57
    Updated at: 2018-12-17 07:48:34
    
    Rating: #0
    Total detections: 3
*/

import "androguard"

rule SignDeskESignSDKTrackerActivity
{
	meta:
		description = "All SignDesk eSign SDK Apps"
	condition:
		androguard.activity("in.signdesk.esignsdk.esign.eSign")
}
