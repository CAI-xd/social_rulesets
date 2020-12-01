/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Mathes
    Rule name: New Ruleset
    Rule id: 7296
    Created at: 2020-11-13 03:20:19
    Updated at: 2020-11-13 09:36:40
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Analysis of application zo31"


	condition:
		androguard.package_name("com.mwusijwro.lrhcm2f4f") and
		androguard.app_name("zo31") and
		androguard.activity(/com.tencent.QActivity/) and
		androguard.activity(/com.ryg.dynamicload.DLProxyFragmentActivity/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALLS/) and
		androguard.certificate.sha1("acda44599b555e7a6cd5ffc3c8963213ac592812") and
		androguard.url(/koodous\.com/) and
		not file.md5("a6bff959690f58942fcc4e52a00efe6d") and 
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
