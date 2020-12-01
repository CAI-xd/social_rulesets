/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Yunana
    Rule name: Yara rule for Part1
    Rule id: 7133
    Created at: 2020-11-04 11:02:00
    Updated at: 2020-11-16 13:45:46
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		sample = "b8d245b62fdb7370aaef0133b62c25c3eb60d2d0f15d8170b2255c26d489a589"

     strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("wteu.cjvow.ldkanccrhcxhrj") and
		androguard.app_name("CORONA TEST") and
		androguard.activity(/wteu.cjvow.ldkanccrhcxhrj.Activity.MainActivity/i) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81") and
		not file.md5("b11e45e1f7f4dca9327a10a572c18623") and
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
