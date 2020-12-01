/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TaroSpruijt
    Rule name: New Ruleset
    Rule id: 7140
    Created at: 2020-11-05 08:11:43
    Updated at: 2020-11-09 20:21:47
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the AntiVirus app by Bechtelar Russel and Reinger"
		sample = "ea4cb7e998f6ec91156c81334cc862a8647642a43ca2dc918b7ef08dd0b54eae"

	strings:
		$a = "http://checkip.amazonaws.com/."
		$b = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"

	condition:
		all of them and
		androguard.package_name(/rkr.simplekeyboard.inputmethod/) or
		androguard.package_name(/com.shopiapps.roastcoffeetraders/) and
		androguard.app_name(/AVG AntiVirus 2020 for Android Security FREE/) and
		androguard.activity(/CryptoCipher/) and
		androguard.activity(/MraidActivity/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.BLUETOOTH/) and
		androguard.certificate.sha1("77452e18a9061094d214a06d9bce8407d01cb74b") and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
