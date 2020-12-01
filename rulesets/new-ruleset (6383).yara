/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: El
    Rule name: New Ruleset
    Rule id: 6383
    Created at: 2020-02-11 12:58:58
    Updated at: 2020-02-11 13:00:40
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "attiva.exodus.esurv.it"
		"

	strings:
		$a = {61 74 74 69 76 61 2e 65 78 6f 64 75 73 2e 65 73 75 72 76 2e 69 74}

	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("Koodous") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139") and
		androguard.url(/koodous\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) 
		
		
}