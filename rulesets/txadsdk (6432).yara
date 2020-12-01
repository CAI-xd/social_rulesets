/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: endlif
    Rule name: txadSDK
    Rule id: 6432
    Created at: 2020-02-28 11:09:28
    Updated at: 2020-02-28 11:17:19
    
    Rating: #0
    Total detections: 198
*/

import "androguard"

rule AtomSDKTracker
{
	meta:
		description = "All Atom SDK Apps"
	condition:
		androguard.activity("com.qq.e.ads.ADActivity")	
}
