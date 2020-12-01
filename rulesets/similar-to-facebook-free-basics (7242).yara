/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Mattias
    Rule name: Similar to "Facebook (Free Basics)"
    Rule id: 7242
    Created at: 2020-11-10 12:30:53
    Updated at: 2020-11-10 12:35:36
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Similar_to_Facebook_Free_Basics
{
	meta:
		description = "This rule detects APK's with the same permissions as the Facebook (Free Basics) APK"

	condition:
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.RECIEVE_SMS/)	
}
