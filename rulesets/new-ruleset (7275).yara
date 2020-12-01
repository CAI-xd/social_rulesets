/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Rens
    Rule name: New Ruleset
    Rule id: 7275
    Created at: 2020-11-12 15:37:51
    Updated at: 2020-11-12 15:45:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e520b9d9d720eca17c9e6438d23fabbf1317fa7badfcfff9bfae057bcb33073d"

	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("com.hd.backupapk") and
		androguard.app_name("Apk Extractor") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("3817b34beedfe3d383b31246e72ba66f10bae633") and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
