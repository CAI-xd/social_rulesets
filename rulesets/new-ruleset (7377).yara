/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: diesmaster
    Rule name: New Ruleset
    Rule id: 7377
    Created at: 2020-11-17 19:44:58
    Updated at: 2020-11-17 21:59:29
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "droidbox"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects malware like the apk we analysed"
		

	condition:
		androguard.package_name("com.siohmxdyozxn.umyrvl") 
		and
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
		and
		droidbox.sendsms(/./) 
		and
		androguard.certificate.sha1("90880a2ef88aaa1b9f2072c87c1b01afaf09b817")
		
}
