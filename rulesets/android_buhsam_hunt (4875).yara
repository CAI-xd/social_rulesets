/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ransombleed
    Rule name: Android_Buhsam_hunt
    Rule id: 4875
    Created at: 2018-09-07 11:57:42
    Updated at: 2018-09-07 12:08:41
    
    Rating: #0
    Total detections: 2285
*/

import "androguard"
import "file"
import "cuckoo"


rule Android_Buhsam_hunt
{
	meta:
		description = "This rule detects the Android Buhsam apk"
		sample = "4bed89b58c2ecf3455999dc8211c8a7e0f9e8950cb9aa83cd825b8372b1eaa3d"
	condition:
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.BATTERY_STATS/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		androguard.permission(/android.permission.CAMERA/) and
		androguard.permission(/android.permission.READ_CALENDAR/) and
		androguard.permission(/android.permission.READ_CALL_LOG/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/com.android.browser.permission.READ_HISTORY_BOOKMARKS/)
		
}
