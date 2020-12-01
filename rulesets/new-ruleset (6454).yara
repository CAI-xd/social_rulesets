/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: El
    Rule name: New Ruleset
    Rule id: 6454
    Created at: 2020-03-09 10:17:16
    Updated at: 2020-03-09 10:17:46
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : sms
{
	meta:
		description = SMS
	

	strings:
		$a = {61 6e 64 72 6f 69 64 2e 70 65 72 6d 69 73 73 69 6f 6e 2e 53 45 4e 44 5f 53 4d 53}

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
