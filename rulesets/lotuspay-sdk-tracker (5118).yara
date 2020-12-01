/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: LotusPay SDK Tracker
    Rule id: 5118
    Created at: 2018-12-09 12:35:31
    Updated at: 2018-12-13 08:14:54
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule LotusPaySDKTrackerActivity
{
	meta:
		description = "All LotusPay SDK Apps"
	condition:
		androguard.activity("com.lotuspay.library.LotusPay")	
}
