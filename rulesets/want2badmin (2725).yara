/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kpatsak
    Rule name: Want2BAdmin
    Rule id: 2725
    Created at: 2017-05-20 13:30:59
    Updated at: 2017-06-20 21:40:16
    
    Rating: #0
    Total detections: 73763
*/

import "androguard"
import "file"
import "cuckoo"


rule Want2Badmin
{
	meta:
		description = "Apps that want to be admins through intents"

	strings:
		$a = "android.app.extra.DEVICE_ADMIN" nocase
		$b = "ADD_DEVICE_ADMIN" nocase
		$c = "DEVICE_ADMIN_ENABLED"

	condition:
		$a or $b or $c
		
}
