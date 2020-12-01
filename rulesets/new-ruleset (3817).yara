/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: poulpi
    Rule name: New Ruleset
    Rule id: 3817
    Created at: 2017-11-07 23:36:33
    Updated at: 2017-11-07 23:38:37
    
    Rating: #0
    Total detections: 7
*/

import "androguard"
import "file"
import "cuckoo"


rule ezeeworld
{
	meta:
		description = "This rule detects application including Ezeeworld SDK"

	condition:
		androguard.receiver("com.ezeeworld.b4s.android.sdk.monitor.SystemEventReceiver")
		
}
