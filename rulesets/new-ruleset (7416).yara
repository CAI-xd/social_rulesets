/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: milanluijken
    Rule name: New Ruleset
    Rule id: 7416
    Created at: 2020-11-20 10:21:56
    Updated at: 2020-11-20 10:37:31
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "1266cfb6ccfcb98f72feb33e61b69b91fdc5869fb160496731284413fb9155ca"

	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("com.dotgears.flappybird") and
		androguard.app_name("fakeflappy.apk") and
		androguard.activity(/com.dotgears.flappy.SplashScreen/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and		
		androguard.certificate.sha1("2003dd0a568976393fefe5801fd60d4706fe7e1f") and
		androguard.url(/koodous\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
