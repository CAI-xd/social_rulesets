/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 5424
    Created at: 2019-04-09 06:52:08
    Updated at: 2019-04-09 06:53:25
    
    Rating: #0
    Total detections: 55
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : SuspiciousBanker_C
{
	meta:
		description = "This rule detects sample based on device_Admin"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a1 = "android.app.action.DEVICE_ADMIN_ENABLED" wide
		$a2 = "android.permission.INTERNET" wide
		$a3 = "android.accessibilityservice.AccessibilityService" wide
		
		$b1 = "android.permission.READ_SMS" wide
		$b2 = "android.permission.SEND_SMS" wide
		$b3 = "android.permission.RECEIVE_SMS" wide
		$b4 = "android.permission.WRITE_SMS" wide
		
		$c1 = "android.permission.WRITE_EXTERNAL_STORAGE" wide
		$c2 = "android.permission.READ_EXTERNAL_STORAGE" wide
		$c3 = "android.permission.READ_PHONE_STATE" wide
		
		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}
		
	condition:
		2 of ($a*) and (3 of ($b*) or (2 of ($b*) and 2 of ($c*))) and $hexstr_targetSdkVersion and filesize < 180KB
	
}
