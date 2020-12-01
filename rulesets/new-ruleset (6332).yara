/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: maya1237
    Rule name: New Ruleset
    Rule id: 6332
    Created at: 2020-01-30 12:10:03
    Updated at: 2020-01-30 12:11:44
    
    Rating: #0
    Total detections: 0
*/

import "androguard"



rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"


	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("Koodous") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139") and
		androguard.url(/koodous\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
