/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: axelleap
    Rule name: CloakAndDagger
    Rule id: 5594
    Created at: 2019-06-06 14:13:40
    Updated at: 2019-06-06 14:16:06
    
    Rating: #0
    Total detections: 242
*/

import "androguard"
import "file"
import "cuckoo"


rule cloak_and_dagger : official
{
	meta:
		description = "Potential Cloak and Dagger attack - http://cloak-and-dagger.org"

	condition:
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
		
}
