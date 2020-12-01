/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yleg
    Rule name: Dagger Ruleset
    Rule id: 5943
    Created at: 2019-10-07 16:34:17
    Updated at: 2019-10-07 16:34:53
    
    Rating: #0
    Total detections: 652
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "First rule used to detect certain permissions"

	condition:
		androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
		
}
