/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kevinmerbis
    Rule name: New Ruleset
    Rule id: 7148
    Created at: 2020-11-06 10:14:07
    Updated at: 2020-11-09 20:12:44
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Trojan : WipeLocker
{
	meta:
		description = "Trojan targeting external storage of android devices"
		sample = "f75678b7e7fa2ed0f0d2999800f2a6a66c717ef76b33a7432f1ca3435b4831e0"

	condition:
		androguard.package_name("com.elite") and
		androguard.app_name("Angry_BirdTransformers") and
		androguard.activity(/com.elite.MainActivity/i) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
}
