/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Evannoels
    Rule name: New Ruleset
    Rule id: 7309
    Created at: 2020-11-13 12:04:02
    Updated at: 2020-11-13 12:14:13
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous :virus_hunter_app
{
	meta:
		description = "virus_hunter_app"
		sample = "cb0666dddffaad7b014aa5999e295e913af5b6df7bad6e9bdf55c3eb82c75493"

	strings:
		$a = "google_maps"
		$b = "billing"
		$c = "location"
		$d = "wifi_change"

	condition:
		$a or $b or $c or $d
		androguard.package_name("com.koodous.android") and
		androguard.app_name("Koodous") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139") and
		androguard.url(/koodous\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
