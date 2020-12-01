/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yleg
    Rule name: Cloak Ruleset
    Rule id: 5923
    Created at: 2019-09-30 17:33:31
    Updated at: 2019-09-30 17:34:12
    
    Rating: #0
    Total detections: 10919
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "First rule used to detect certain permissions"

	condition:
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/)
		
}
