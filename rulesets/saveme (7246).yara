/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Mattias
    Rule name: SaveMe
    Rule id: 7246
    Created at: 2020-11-10 16:29:02
    Updated at: 2020-11-10 16:59:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule SaveMe
{
	meta:
		description = "This rule detects APK's similar to SaveMe"
		
	strings:
		$a = "android.intent.action.CALL"
		$b = "content://call_log/calls"
		
		
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		$a and
		$b
}
