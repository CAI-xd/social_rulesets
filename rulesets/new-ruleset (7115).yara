/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: s2669668
    Rule name: New Ruleset
    Rule id: 7115
    Created at: 2020-11-02 14:16:21
    Updated at: 2020-11-02 14:38:57
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Cajino
{
	meta:
		description = "This rule tries to detects push notification malware also kwnown as Cajino"
		sample = "31801dfbd7db343b1f7de70737bdbab2c5c66463ceb84ed7eeab8872e9629199"

	condition:
		androguard.package_name("Cajino_B3814CA9E42681B32DAFE4A52E5BDA7A") or
		androguard.app_name("Cajino") or
        androguard.activity("com.package.name.sendSMS") and
		androguard.activity("com.baidu.android.pushservice.action.MESSAGE") and
		androguard.activity("com.baidu.android.pushservice.action.RECIEVE") and
		androguard.activity("com.baidu.android.pushservice.action.notification.CLICK")and
		androguard.activity("android.intent.action.VIEW") or
		androguard.permission(/RECORD_AUDIO/) and
		androguard.permission(/ACCESS_FINE_LOCATION/) 
		
}
