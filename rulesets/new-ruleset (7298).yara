/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Matthijs
    Rule name: New Ruleset
    Rule id: 7298
    Created at: 2020-11-13 10:05:29
    Updated at: 2020-11-13 12:37:51
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : Adware
{
	meta:
		description = "This rule detects the com.fastfood_recipes application"
		sample = "cb9c44fd146a3f05c04d5e62abed611e01e5a431ee570fa635423689f3c98d4f"

	strings:
		$a = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"

	condition:
		androguard.package_name("com.fastfood_recipes") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.BLUETOOTH/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.certificate.sha1("f2ea77200808caaa94447b601e41b9c0bc470eb6")	and
		$a
}
