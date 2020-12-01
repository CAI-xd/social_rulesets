/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lisav
    Rule name: New Ruleset
    Rule id: 7129
    Created at: 2020-11-03 10:36:41
    Updated at: 2020-11-10 12:51:27
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Trojan : BatterySuperCharger
{
	meta:
		description = "This rule detects the Battery SuperCharger application, using permission and activity"
		sample = "269e98e6d6020cc611321c58af75fe9d8ae5ff8a"

	condition:
		androguard.package_name("com.extend.battery") and
		androguard.app_name("Battery SuperCharger") and
		androguard.activity(/com.extend.battery.Splash/i) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.certificate.sha1("269e98e6d6020cc611321c58af75fe9d8ae5ff8a") and
		not file.md5("5e3fcd800f7b8db5a59554459e110f4d") and 
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
