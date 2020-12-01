/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Dinoah
    Rule name: New Ruleset
    Rule id: 7268
    Created at: 2020-11-12 13:56:12
    Updated at: 2020-11-12 15:31:23
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This is a rule to identify TopSecretVideo and similar malicious apks."
		sample = "f87926a286ecc487469c7b306e25818995fecd3be704a2381d676b9725c647b4"

	strings:
		$a = "http://schemas.android.com/apk/res/android"

	condition:
		androguard.package_name("org.pairjesterutterly") and
		androguard.app_name("TopSecretVideo") and
		androguard.activity(/org.pairjesterutterly.MainActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.certificate.sha1("6a96e534d7aae84b989859ac9c20c5adb5da2507") and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/)
		
		
}
