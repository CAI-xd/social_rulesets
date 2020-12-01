/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: El
    Rule name: New Ruleset
    Rule id: 6384
    Created at: 2020-02-11 13:18:25
    Updated at: 2020-02-11 13:19:06
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Shopper.a"
		

	strings:
		$a = {68 74 74 70 3a 2f 2f 61 70 69 2e 61 64 73 6e 61 74 69 76 65 31 32 33 5b 2e 5d 63 6f 6d}

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
