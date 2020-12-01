/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Cyberassignment
    Rule name: Fresh Cleaner
    Rule id: 7223
    Created at: 2020-11-09 22:35:46
    Updated at: 2020-11-10 11:59:32
    
    Rating: #1
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the Fresh cleaner application, a Trojan 							used to gain backdoor access"
		sample = "c0403093672b782d2a95fe5cf5ce8bc4"
		reference = 
		"https://koodous.com/apks/abd99e70679da305251c8d2c38b4364b9c919a88aa144cd0e5ea65fdf598d664"


	strings:
		$a = "http://ELB-API-127-1069859428.ap-southeast-1.elb.amazonaws.com/in"

	condition:
		androguard.package_name("com.fresh.cleaner") and
		androguard.app_name("Fresh Cleaner") and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.PACKAGE_USAGE_STATS/)   
		and $a 
		
		 
}
