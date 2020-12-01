/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pgapk1
    Rule name: New Ruleset
    Rule id: 2946
    Created at: 2017-06-08 07:34:20
    Updated at: 2017-06-08 07:34:29
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("Koodous") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139") and
		androguard.url(/koodous\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
