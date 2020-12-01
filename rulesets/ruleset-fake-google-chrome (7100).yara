/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Bvlampe
    Rule name: Ruleset: fake google chrome
    Rule id: 7100
    Created at: 2020-10-28 19:27:59
    Updated at: 2020-11-10 10:25:17
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects a variation of Google Chrome lookalikes"
		sample = "786544eff4d873427827ccecbf96e3341da09b94a20c1b0a5a29ed47921b83d4"


	condition:
		androguard.package_name("gayk.hqcwj.ndsec") and
		androguard.app_name("Chrome") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		androguard.certificate.sha1("13586b6fe4f5d4c16e17d8b1b6c43883708125e3") and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
