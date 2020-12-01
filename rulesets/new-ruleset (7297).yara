/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Mathes
    Rule name: New Ruleset
    Rule id: 7297
    Created at: 2020-11-13 03:30:35
    Updated at: 2020-11-13 09:34:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Detection of DroidKungFu malware"

	condition:
		androguard.package_name("com.allen.txthej") and
		androguard.app_name("80612fe193401626268553c54a865e67b76311e782005ede2ba7a87a5d637420.apk") and
		androguard.activity(/com.allen.txthej.txtReader (com.allen.txthej)/i) and
		androguard.activity(/com.allen.txthej.ViewFileAct_Float (com.allen.txthej)/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/)and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/)and
		androguard.permission(/android.permission.READ_PHONE_STATE/)and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)and
		androguard.certificate.sha1("	35b223e521abc1cb6b8043f95c2a133c11ed8be4") and
		androguard.url(/koodous\.com/) and
		not file.md5("	f438ed38b59f772e03eb2cab97fc7685") and 
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
