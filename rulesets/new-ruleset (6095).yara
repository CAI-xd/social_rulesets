/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: liuyun
    Rule name: New Ruleset
    Rule id: 6095
    Created at: 2019-11-06 06:20:47
    Updated at: 2019-11-06 06:25:51
    
    Rating: #0
    Total detections: 48
*/

import "androguard"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
	

	strings:
		$a = /taskAffinity\s*=/
		$b = /allowTaskReparenting\s*=/
		$file = "AndroidManifest.xml"

	condition:
		$file and ($a or $b)
		
}
