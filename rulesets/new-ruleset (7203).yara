/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Christie
    Rule name: New Ruleset
    Rule id: 7203
    Created at: 2020-11-09 15:34:22
    Updated at: 2020-11-10 09:49:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Rule to detect Cajino"
		sample = "Cajino_B3814CA9E42681B32DAFE4A52E5BDA7A"

	strings:
		$a = "/update/update.apk"
		$b = "application/vnd.android.package-archive"

	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("Koodous") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.READ_CALL_LOG/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.READ_PHONE_NUMBERS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.url("http://kharon.gforge.inria.fr\\dataset\\malware_Cajino.html") and 
		$a and 
		$b and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
