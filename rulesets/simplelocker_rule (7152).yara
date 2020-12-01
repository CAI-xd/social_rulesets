/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Tessadejong
    Rule name: SimpleLocker_Rule
    Rule id: 7152
    Created at: 2020-11-06 13:27:54
    Updated at: 2020-11-06 14:04:20
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"


rule Simplelocker_Rule
{
	meta:
		description = "This rule detects the Simplelocker application"

	strings:
		$text_string = "privoxy.config"
		$text_in_hex = { 70 72 69 76 6f 78 79 2e 63 6f 6e 66 69 67 }
		$text_string2 = "FILES_WAS_ENCRYPTED"
		$text_in_hex2 = { 46 49 4c 45 53 5f 57 41 53 5f 45 4e 43 52 59 50 54 45 44 }
		$text_string3 = "WakeLock"
		$text_in_hex3 = { 57 61 6b 65 4c 6f 63 6b }
		$text_string4 = "DISABLE_LOCKER"
		$text_in_hex4 = { 44 49 53 41 42 4c 45 5f 4c 4f 43 4b 45 52 }
		
	condition:
		androguard.package_name("org.simplelocker") and
		androguard.app_name("SimpleLocker") and
		androguard.activity(/Details_Activity/i) and
		$text_string and
		$text_in_hex and
		$text_string2 and
		$text_in_hex2 and
		$text_string3 and
		$text_in_hex3 and
		$text_string4 and
		$text_in_hex4
	
}
