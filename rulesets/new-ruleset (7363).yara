/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: throwaway2002
    Rule name: New Ruleset
    Rule id: 7363
    Created at: 2020-11-17 16:24:28
    Updated at: 2020-11-17 18:34:02
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule findSimilar : official
{
	meta:
		description = "Detects similar apk's as analyzed in the assignment. Written by: Jack Voorham and Chris Maarseveen"
		sample = "85ad97b0c6046b35ec74034d28083ea578c887bab933b044bf7930df20c2b8cc"
	strings:
        $activity = "Landroid/app/Activity;->navigateUpTo"
	condition:
		/* Check permissions */
		androguard.permission(/android.permission.GET_ACCOUNTS/) 
		and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) 
		and
		androguard.permission(/android.permission.READ_PHONE_STATE/) 
		and
		androguard.permission(/android.permission.QUICKBOOT_POWERON/)
		and 
		androguard.permission(/android.permission.READ_CONTACTS/)
		and 
		androguard.permission(/android.permission.WRITE_CONTACTS/)
		and
	    androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		and 
		androguard.permission(/android.permission.VIBRATE/)
		and
		androguard.permission(/android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/)
		and
		androguard.permission(/android.permission.READ_SMS/)
		and 
		androguard.permission(/android.permission.RECEIVE_SMS/)
		and
	    androguard.permission(/android.permission.SEND_SMS/)
		and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)
		and
	    androguard.permission(/android.permission.INTERNET/)
		and
		androguard.permission(/android.permission.FOREGROUND_SERVICE/)
		and
	    androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
		and
	    androguard.permission(/android.permission.WAKE_LOCK/)
		/* Check permissions that are needed but not in the androidmanifest */
		and
		($activity and not androguard.permission(/android.permission.BROADCAST_STICKY/))
	    /* Check if apk is not the apk we analyzed */
		and not 
		file.md5("edcea298b04405df61c1ddde8142244e")
}
