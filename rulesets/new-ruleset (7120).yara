/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Sterre
    Rule name: New Ruleset
    Rule id: 7120
    Created at: 2020-11-03 09:28:53
    Updated at: 2020-11-03 09:53:06
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule koodous : official
{
	meta:
		description = "This rule detects potential banking trojans with the interface of Chrome"
		sample = "f46c90ffd4b15655f00a0fc5cb671cc9f55f2a21457913af940b9dd32f286307"
	
	condition:	
	androguard.permission(/android.permission.SYSTEM_OVERLAY_WINDOW/) and
	androguard.permission (/android.permission.DISABLE_KEYGUARD/) and
	androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/)
		
		
}
