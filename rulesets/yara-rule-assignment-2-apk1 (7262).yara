/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lucschouten
    Rule name: YARA rule assignment 2, apk1
    Rule id: 7262
    Created at: 2020-11-11 16:39:31
    Updated at: 2020-11-12 20:12:33
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule trojan {
	meta:
		description = "Yara rule to find trojan apps"
		author = "Luc Schouten & Dylan macquine"
		date = "11-11-2020"
		sample = "23e6b3d76fcaf00f03c2bd0ce05f0f67e2cdba86dab61450f421e501d756e8ac"
		
	strings:
	  $function1 = "SmsReceiver;->abortBroadcast"

	condition:
		(androguard.permission(/android.permission.READ_SMS/) and androguard.permission(/android.permission.RECEIVE_SMS/) and androguard.permission(/android.permission.WRITE_SMS/) and androguard.permission(/android.permission.SEND_SMS/) and $function1) and (androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) or androguard.permission(/android.permission.READ_PHONE_STATE/) or androguard.permission(/android.permission.GET_TASKS/)) and androguard.app_name(/battery/)
		
}
