/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: danvdboo
    Rule name: SecurityAss2
    Rule id: 7331
    Created at: 2020-11-16 14:36:52
    Updated at: 2020-11-16 15:08:51
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects apks that uses permissions which it should definitely not be able to use."
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
		androguard.package_name("com.bzyg.zhongguozhexuejianshi") and
		androguard.app_name("A Brief History of Chinese Philosophy") and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.ADD_VOICEMAIL/) and
		androguard.certificate.sha1("1dab0a0d4123f6fc17b78ee327b1b219b951f546")
		
}
