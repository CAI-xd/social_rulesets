/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: secauvr2
    Rule name: generic overlap and rat
    Rule id: 5283
    Created at: 2019-02-14 21:58:35
    Updated at: 2019-02-14 22:00:46
    
    Rating: #0
    Total detections: 7
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = ".php"

	condition:
		(androguard.app_name("atualiza") or androguard.app_name("whatsapp")) and
		androguard.permission(/android.permission.INTERNET/) and
	    androguard.permission(/android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
        androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.GET_ACCOUNTS/) and
		$a		
}
