/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ezbircime
    Rule name: New Ruleset
    Rule id: 7261
    Created at: 2020-11-11 16:22:09
    Updated at: 2020-11-12 22:38:29
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "qq [NOT DETECTED]"
		sample = "041316520f3dfc5c4ffa022fb5846164884001c577ec3c4601625cd56ae7998f"

	strings:
		$a = {68 74 74 70 3a 2f 2f 78 6d 6c 70 75 6c 6c 2e 6f 72 67 2f 76 31 2f 64 6f 63 2f 66 65 61 74 75 72 65                 73 2e 68 74 6d 6c 23 69 6e 64 65 6e 74 2d 6f 75 74 70 75 74}

	condition:
		androguard.package_name("com.hughu") and
		androguard.app_name("qq [NOT DETECTED]") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/)and 
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALLS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.certificate.sha1("96990fd4a27421dc1a0f5226566da6dd6b1706c5") and
		not file.md5("6f73d48c937e9ddecdba7b356948b1b2") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) 
		
}
