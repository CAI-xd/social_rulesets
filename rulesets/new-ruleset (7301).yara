/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: thomasblom98prive
    Rule name: New Ruleset
    Rule id: 7301
    Created at: 2020-11-13 11:02:09
    Updated at: 2020-11-13 12:00:08
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "2a401f97cba6b6fcfdb849efff9835b613d691a7a68cf86ed2a9e6ecf733c998"

	strings:
	$a = {23 43 DC C2 32 F2 51 AE AA 00 88 88 E2 6B D1 29 63}

	condition:
		androguard.package_name("com.dotgears.flappybird") and
		androguard.app_name("Flappy Bird") or
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.CAMERA/) and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.READ_CALL_LOG/) and
		androguard.permission(/android.permission.PHONE_STATE/) and
		androguard.permission(/android.permission.READ_SMS/) and
		$a 
		
}
