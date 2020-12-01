/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ddoekes
    Rule name: Location detection rule
    Rule id: 7270
    Created at: 2020-11-12 14:09:34
    Updated at: 2020-11-12 23:09:35
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects applications that use location permissions"
		sample = "ada819d7b6f9fa415e4e8f2079e6b8543239f9c949f1e76d19726e2338eaa983"

	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("pra.hizzahut.com.sv") and
		androguard.app_name("Pizza Hut SV") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_COURSE_LOCATION/) and									               		   androguard.certificate.sha1("e7230276ffe2cadf17d030cdcb74f0fc9eb3e2b1") and
		androguard.url(/koodous\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
