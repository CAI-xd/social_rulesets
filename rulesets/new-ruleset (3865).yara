/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: tal_93
    Rule name: New Ruleset
    Rule id: 3865
    Created at: 2017-12-04 12:17:21
    Updated at: 2017-12-04 12:18:59
    
    Rating: #0
    Total detections: 264092
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects apps with bluetooth permissions"
		

	condition:
		androguard.permission(/android.permission.BLUETOOTH/) or
		androguard.permission(/android.permission.BLUETOOTH_ADMIN/)
		
}
