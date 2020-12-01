/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: respect4corona
    Rule name: New Ruleset
    Rule id: 7282
    Created at: 2020-11-12 16:11:40
    Updated at: 2020-11-12 23:32:49
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Virus cleaner"
		sample = "700bea9c4f336def1801d3f7bdb2ce5f79cdf42d9b2fe3991f1128fa43dfd2a1"

	strings:
		$a = {68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 61 6e 64 72 6f 69 64 2e 63 6f 6d 2f 61 				70 6b 2f 72 65 73 2f 61 6e 64 72 6f 69 64}

	condition:
		androguard.package_name("com.com.energycoach") and
		androguard.app_name("Virus Cleaner") and
		androguard.activity(/ru.wellapp.bukvica.MainActivity/i) and
		androguard.activity(/ru.wellapp.bukvica.LastActivity/i) and
		androguard.activity(/com.improof.reinitiation.UploadActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.certificate.sha1("85971086ab30630009477906b980b8c7a031ba5c") and
		not file.md5("8b6a544ee4f3a12b108f044a140feae9") and
		$a and 
		cuckoo.network.dns_lookup(/startup.mobile.yandex.net/) //
}
