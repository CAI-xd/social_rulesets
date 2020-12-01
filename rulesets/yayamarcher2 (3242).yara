/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaMarcher2
    Rule id: 3242
    Created at: 2017-07-27 00:32:28
    Updated at: 2017-07-27 00:33:28
    
    Rating: #0
    Total detections: 78
*/

import "androguard"


 rule YaYaMarcher2  {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"
		date = "13 Jul 2017"
		original = "1301:Marcher2"

	condition:
		androguard.filter("MainActivity.AlarmAction") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.MAIN") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.filter("com.KHLCert.fdservice") and 
		androguard.filter("com.KHLCert.gpservice") and 

		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.CALL_PHONE") and 
		androguard.permission("android.permission.CHANGE_NETWORK_STATE") and 
		androguard.permission("android.permission.CHANGE_WIFI_STATE") and 
		androguard.permission("android.permission.GET_TASKS") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_CONTACTS") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.RECEIVE_SMS") and 
		androguard.permission("android.permission.SEND_SMS") and 
		androguard.permission("android.permission.USES_POLICY_FORCE_LOCK") and 
		androguard.permission("android.permission.VIBRATE") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_SETTINGS") and 
		androguard.permission("android.permission.WRITE_SMS")
}
