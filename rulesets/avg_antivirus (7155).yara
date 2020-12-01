/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Tessadejong
    Rule name: AVG_AntiVirus
    Rule id: 7155
    Created at: 2020-11-06 14:05:59
    Updated at: 2020-11-06 14:25:06
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"


rule AVG_AntiVirus
{
	meta:
		description = "This rule detects the AVG AntiVirus application"

	strings:
		$text_string = "getDeviceId"
		$text_in_hex = { 6765744465766963654964 }

	condition:
		androguard.package_name("com.fadwapro.momalahat.sahla") and
		androguard.app_name("AVG AntiVirus 2020 for Android Security FREE") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and	
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and  
		androguard.certificate.sha1("e423ef06360cf9a1c1b1c9b2f2cd51ae466a1f5a") and
		not file.md5("8ef6facf343ce0373597873be66bde8f") and 
		$text_string and
		$text_in_hex	
}
