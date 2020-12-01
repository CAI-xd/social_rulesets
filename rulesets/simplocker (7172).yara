/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: annod69
    Rule name: SimpLocker
    Rule id: 7172
    Created at: 2020-11-08 20:07:55
    Updated at: 2020-11-08 20:36:56
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule SimpLocker
{
	meta:
		description = "This rule aims to detect SimpLocker and other related ransomware"
	

	strings:
		$a = "simplelocker"

	condition:
		$a or
		androguard.app_name("Sex xionix") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
		
}
