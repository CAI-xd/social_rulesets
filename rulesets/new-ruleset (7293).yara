/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ssouf98
    Rule name: New Ruleset
    Rule id: 7293
    Created at: 2020-11-12 20:19:42
    Updated at: 2020-11-12 20:46:54
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule privacy_and_adware_detection : privacy_and_adware
{
	meta:
		description = "This rule detects adware and/or potential privacy violating elements of the mightyfrog app and/or other element in the fish.rezepte package "
		weight = 6

	strings:
		$a = "internet"

	condition:
		androguard.package_name("com.fish.Rezepte.de") and
		androguard.app_name("mightyfrog") and
		$a and
		
		
		(
		(androguard.activity(/LinkActivity/i) and
		androguard.activity(/BannerActivity/i) and
		androguard.activity(/InAppPushActivity/i))
		
		or 
		
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/))
		)
}
