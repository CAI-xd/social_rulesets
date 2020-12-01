/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jvonk123
    Rule name: New Ruleset
    Rule id: 7276
    Created at: 2020-11-12 15:46:07
    Updated at: 2020-11-12 21:20:06
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Bad_news : badnews
{
	meta:
		description = "This Yara rule detects things familiar to badnews"

	strings:
		$a = "newdomen"
		$b = "seconddomen"
		$c = "status"
		$d = "iconinstall"

	condition:
		androguard.package_name("com.mobidisplay.advertsv1") and
		androguard.app_name("Badnews") and
		androguard.url(/xxxplay.net/ ) and
		
		(androguard.permission(/android.permission.INTERNET/) and
		$a and
		$c)
		
		or
		
		(androguard.permission(/android.permission.INTERNET/) and
		$b and
		$c)
		
		or
		
		(androguard.permission(/android.permission.INTERNET/) and
		$d and
		$c)
}
