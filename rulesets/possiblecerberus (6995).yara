/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Fr4
    Rule name: possibleCerberus
    Rule id: 6995
    Created at: 2020-07-06 15:27:47
    Updated at: 2020-07-06 15:28:08
    
    Rating: #0
    Total detections: 0
*/

rule android_bankbot
{
	meta:
		description = "This rule detects possible android bankbot like Cerberus or Anubis"

	strings:
		$a = "accessibilityservice"

	condition:
		$a and 
        androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
        androguard.permission(/android.permission.SEND_SMS/) and
        androguard.permission(/android.permission.WAKE_LOCK/) and
        androguard.permission(/android.permission.RECEIVE_SMS/) and
        androguard.permission(/android.permission.READ_SMS/) and
        androguard.permission(/android.permission.RECORD_AUDIO/) and
        androguard.permission(/android.permission.READ_PHONE_STATE/) and
        androguard.permission(/android.permission.FOREGROUND_SERVICE/) and
        androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
        androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
        androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
        androguard.permission(/android.permission.CALL_PHONE/) and
        androguard.permission(/android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
        androguard.permission(/android.permission.READ_CONTACTS/)
}
