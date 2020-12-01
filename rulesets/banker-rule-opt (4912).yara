/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: Banker rule opt
    Rule id: 4912
    Created at: 2018-09-27 12:09:02
    Updated at: 2018-09-27 12:09:10
    
    Rating: #0
    Total detections: 3
*/

import "androguard"
import "cuckoo"


rule YaYa: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.5_summer18"
		date = "27 Sep 2018"
		url = "https://koodous.com/apks?search=c2f8d276c497c571ac55346528af93d2e86d04d6e02e91a30e4cf44f125ae7c0%20OR%20%20f28d365c2b75b96faffa28eee85afddae8a2c6f1490e8294fb67e79874a7ff5c%20OR%20%20d0e28ee49d7b7feb5f94dbd00e4f5a6e4f418b536229188ef86bf45008c34d9b%20OR%20%208eb215552d186fdc24b53e34028e41e9e680ae1b32915f4b5c1a853142cdae8a"

	condition:
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.filter("com.android.vending.INSTALL_REFERRER") and 
		androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON") and 

		androguard.functionality.crypto.method(/getErrorMessage/) and 
		androguard.functionality.imei.method(/onTokenRefresh/) and 

		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.SEND_SMS")
}
