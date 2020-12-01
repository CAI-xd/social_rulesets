/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jg27
    Rule name: New Ruleset
    Rule id: 7077
    Created at: 2020-10-05 15:18:40
    Updated at: 2020-10-07 20:07:59
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule Cerberus_Permissions 
{
	meta:
		description = "Test Rule For Cerberus Permissions"


	condition:
		
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
        androguard.permission(/android.permission.CALL_PHONE/) and
        androguard.permission(/android.permission.FOREGROUND_SERVICE/) and 
        androguard.permission(/android.permission.GET_ACCOUNTS/) and
        androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.READ_CONTACTS/) and
        androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and  
        androguard.permission(/android.permission.READ_PHONE_STATE/) and 
        androguard.permission(/android.permission.READ_SMS/) and 
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 
        androguard.permission(/android.permission.RECEIVE_SMS/) and 
        androguard.permission(/android.permission.RECORD_AUDIO/) and
        androguard.permission(/android.permission.REQUEST_DELETE_PACKAGES/) and 
        androguard.permission(/android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and 
    	androguard.permission(/android.permission.SEND_SMS/) and
        androguard.permission(/android.permission.USE_FULL_SCREEN_INTENT/) and
        androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)   
        
		
}
