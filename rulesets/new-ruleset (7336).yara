/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: hackerman
    Rule name: New Ruleset
    Rule id: 7336
    Created at: 2020-11-16 15:23:59
    Updated at: 2020-11-16 17:08:35
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

//https://koodous.com/rulesets/7336/apks
rule fake_updater
{
	meta:
		description = "This rule detects malicious software based on a fake google play store updater"
		sample = "1dbf4530efd1bab8e298c4553f7873372511b4159a35de446716fd9ae60b6ecb"
				

	strings:
		$a = "android/telephony/TelephonyManager;->getDeviceId"
		$b = "android/telephony/TelephonyManager;->getSimSerialNumber"
		$c = "android/telephony/TelephonyManager;->getLine1Number"
		$d = "android/telephony/TelephonyManager;->getSubscriberId"
		$e = "android/app/ActivityManager;->getRunningTasks"
		$f = "android/net/ConnectivityManager;->getActiveNetworkInfo"
		$g = "android/telephony/SmsManager;->sendTextMessage"
		

	condition:
		any of them
		
}
