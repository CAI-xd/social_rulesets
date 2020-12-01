/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Dinoah
    Rule name: New Ruleset
    Rule id: 7273
    Created at: 2020-11-12 14:57:56
    Updated at: 2020-11-12 15:38:35
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects BadNews and similar malicious  applications"
		sample = "2ee72413370c543347a0847d71882373c1a78a1561ac4faa39a73e4215bb2c3b"

	condition:
		androguard.package_name("com.mobidisplay.advertsv1") and
		androguard.app_name("BadNews") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.url(/http://xxxplay.net/api/adv.php/) and
		not file.md5("474e37797d3106df25c87151876222f4") and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/)
		
		
}
