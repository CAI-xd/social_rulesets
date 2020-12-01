/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 5634
    Created at: 2019-06-20 11:24:12
    Updated at: 2019-06-20 11:25:54
    
    Rating: #0
    Total detections: 258
*/

import "androguard"
import "file"
import "cuckoo"


rule Android_Trojan_SuspiciousPermission_LauncherMiss
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
		$exclude = "android.intent.category.LAUNCHER" wide

		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}
		
	condition:
		#permission <= 15 and $hexstr_targetSdkVersion and not ($exclude) and 2 of ($a*) and 1 of ($b*)

}
