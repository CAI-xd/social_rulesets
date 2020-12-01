/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Erikvv
    Rule name: New Ruleset
    Rule id: 6810
    Created at: 2020-03-30 14:20:12
    Updated at: 2020-03-30 14:23:09
    
    Rating: #0
    Total detections: 12
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "04df74589825e8d93f44a5713769c5a732282c5af9ac699663943824903dfe2b"

	strings:
		$a = "french_cuisine"

	
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and $a
		
		
}
