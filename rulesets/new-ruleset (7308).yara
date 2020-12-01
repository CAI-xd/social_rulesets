/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: thomasblom98prive
    Rule name: New Ruleset
    Rule id: 7308
    Created at: 2020-11-13 12:02:37
    Updated at: 2020-11-13 12:27:28
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules 	potential"
	strings:
		$a = "com.mobidisplay.advertsv1.AdvService"
		$b = "AdvService Started"

	condition:
		androguard.package_name("com.mobidisplay.advertsv1") or
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		$a and
		$b
		
}
