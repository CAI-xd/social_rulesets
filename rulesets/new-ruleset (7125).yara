/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Sterre
    Rule name: New Ruleset
    Rule id: 7125
    Created at: 2020-11-03 09:58:35
    Updated at: 2020-11-03 10:27:08
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects Cajino applications"
		sample = "B3814CA9E42681B32DAFE4A52E5BDA7A"

	condition:
		androguard.app_name("Cajino") and
		androguard.activity(/com.baidu.android.pushservice.action.RECEIVE/) and
		androguard.activity(/com.baidu.android.pushservice.action.MESSAGE/) and
		androguard.activity(/com.baidu.android.andpushservice.action.notification.CLICK/) and
		androguard.permission(/android.permission.CALL_LOG/) and
		androguard.permission(/android.permission.UPLOAD_MESSAGE/) and
		androguard.permission(/android.permission.SEND_MESSAGE/) 
		
}
