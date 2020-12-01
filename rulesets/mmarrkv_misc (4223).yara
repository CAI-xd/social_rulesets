/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mmarrkv
    Rule name: mmarrkv_misc
    Rule id: 4223
    Created at: 2018-02-21 13:46:46
    Updated at: 2018-02-21 14:10:57
    
    Rating: #0
    Total detections: 5534
*/

import "androguard"
import "file"
import "cuckoo"


rule rule1 : mmarrkv_misc
{
	meta:
		description = "Test rule"

	condition:
		androguard.permission(/SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/BIND_ACCESSIBILITY_SERVICE/)
		
}
