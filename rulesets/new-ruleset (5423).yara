/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 5423
    Created at: 2019-04-09 06:50:49
    Updated at: 2019-04-09 06:51:00
    
    Rating: #0
    Total detections: 169
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : SuspiciousPermission_D
{
	meta:
		description = "Check Sample based on the suspicious permission"
		sample = ""

	strings:
		
$a1 = "android.permission.SYSTEM_ALERT_WINDOW" wide
		$a2 = "android.permission.INTERNET" wide
		
		$b1 = "android.permission.READ_SMS" wide
		$b2 = "android.permission.SEND_SMS" wide
		$b3 = "android.permission.RECEIVE_SMS" wide
		$b4 = "android.permission.WRITE_SMS" wide
		
		$c1 = "android.permission.WRITE_EXTERNAL_STORAGE" wide
		$c2 = "android.permission.READ_EXTERNAL_STORAGE" wide
		$c3 = "android.permission.READ_PHONE_STATE" wide
		
		$d1 = "android.permission.READ_CONTACTS" wide
		$d2 = "android.permission.WRITE_CONTACTS" wide
		$d3 = "android.permission.KILL_BACKGROUND_PROCESSES" wide
		$d4 = "com.android.launcher.permission.INSTALL_SHORTCUT" wide
		
		$e1 = "com.android.launcher.permission.UNINSTALL_SHORTCUT" wide
		$e2 = "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION" wide
		$e3 = "android.permission.SYSTEM_OVERLAY_WINDOW" wide
		
		$exclude1 = "com.stone.sdkcore.base" wide
		$exclude2 = "com.paypal.android.sdk" wide
		$exclude3 = "xiaomi" wide
		$exclude4 = "HOTLIST_FM_PUSH" wide
		$exclude5 = "mobilesafe" wide
		$exclude6 = ".samsung." wide
		$exclude7 = "com.facebook.sdk." wide
		$exclude8 = "GRANT_RUNTIME_PERMISSIONS" wide
		$exclude9 = "appstore.battery" wide
		$exclude10 = "com.google.android.c2dm.permission.RECEIVE" wide	
		$exclude11 = "accountsdk.auth" wide
		$exclude12 = "android.permission.WRITE_SECURE_SETTINGS" wide
		$exclude13 = "android.permission.UPDATE_DEVICE_STATS" wide
		$exclude14 ="android.settings.ADD_ACCOUNT_SETTINGS" wide
		$exclude15 ="android.permission.BLUETOOTH_ADMIN" wide
		$exclude16 ="com.google.android.gms.permission.ACTIVITY_RECOGNITION" wide
		$exclude17 ="com.baidu" wide

		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}
		
	condition:
		$hexstr_targetSdkVersion and not (any of ($exclude*)) and filesize < 40KB and
		(
			(
				all of ($a*) 
				and 
				(
					(3 of ($b*)) or (2 of ($b*) and 2 of ($c*)) or (2 of ($c*) and (2 of ($d*) or 1 of ($e*)))
				)
			) 
			or
			($a2 and 3 of ($b*) and 2 of ($c*) and (2 of ($d*) or ( 1 of ($d*) and 1 of ($e*))))
		
		)	

		
}
