/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: IDFCUPICLTracker
    Rule id: 5318
    Created at: 2019-02-26 08:16:57
    Updated at: 2019-02-26 08:17:00
    
    Rating: #0
    Total detections: 1
*/

import "androguard"

rule IDFCUPICLTracker
{
	meta:
		description = "All IDFC UPI SDK Apps"
	condition:
		androguard.activity("com.fss.idfc.idfcupicl")
}
