/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 5778
    Created at: 2019-07-24 08:42:30
    Updated at: 2019-07-24 08:47:11
    
    Rating: #0
    Total detections: 199
*/

import "androguard"
import "file"
import "cuckoo"


rule Android_Trojan_SuspiciousPermission_LauncherMiss_Change1
{
	meta:
		Updated_description = "rules checks the missing launcher"
	
	strings:
	
		$a1 = "android.permission.READ_SMS" wide
		$a2 = "android.permission.SEND_SMS" wide
		$a3 = "android.permission.RECEIVE_SMS" wide
		$a4 = "android.permission.WRITE_SMS" wide
		$a5 = "android.permission.READ_CONTACTS" wide
		$a6 = "android.permission.WRITE_CONTACTS" wide
		
		$b1 = "android.permission.WRITE_EXTERNAL_STORAGE" wide
		$b2 = "android.permission.READ_EXTERNAL_STORAGE" wide
		$b3 = "android.permission.RECEIVE_BOOT_COMPLETED" wide
		$b4 = "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION" wide
		$b5 = "android.permission.SYSTEM_OVERLAY_WINDOW" wide
		
		$permission = "android.permission." wide
		
		$LauncherMissing = "android.intent.category.LAUNCHER" wide
		$exclude_2 = "samsung" wide
		$exclude_3 = "mediatek" wide
		$exclude_4 = "oopo" wide
		$exclude_5 = "xiaomi" wide
		$exclude_6 = "huawei" wide
		$exclude_7 = "motorola" wide
		
		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}
		
	condition:
		#permission >= 10 and $hexstr_targetSdkVersion and not ($LauncherMissing) and not (any of ($exclude_*)) and 2 of ($a*) and 2 of ($b*)
}
