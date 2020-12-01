/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: trollface911
    Rule name: New Ruleset
    Rule id: 7316
    Created at: 2020-11-14 11:26:34
    Updated at: 2020-11-14 11:31:32
    
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
		sample = "c4ac75b5fa46ced6e72b7cb796e76255f70262d74519e4af46a3613c1b3010eb"

	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("com.wc.xiaoyu") and
		androguard.app_name("Calculator") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("f57f1d7f8821626614186ab7cbfc59fb5a788fb3") and
		androguard.url(/koodous\.com/) and
		not file.md5("283af1c612124bf2cdcb8495027c84b1") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
