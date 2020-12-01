/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mhalsema
    Rule name: blockrogue
    Rule id: 7405
    Created at: 2020-11-18 11:59:25
    Updated at: 2020-11-18 12:24:22
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule blockrogue : detect
{
	meta:
		description = "Yara rule made for an assignment"
	condition:
		(
		androguard.app_name("Block Rogue") or
		androguard.app_name("Rogue") or
		androguard.app_name("Block")
		) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATUS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATUS/) and
		androguard.min_sdk >= 8 and
        androguard.target_sdk <= 14 
}
