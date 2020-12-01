/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Disane
    Rule name: AndroidOS.Godless
    Rule id: 1481
    Created at: 2016-06-06 12:42:02
    Updated at: 2016-07-05 09:33:19
    
    Rating: #0
    Total detections: 221
*/

import "androguard"
import "file"
import "cuckoo"


rule Godless
{
	meta: 
		description = "This rule detects the AndroidOS.Godless Auto-Rooting Trojan"

	strings:
		$a = "KEY_REUEST_TEMP_ROOT"
		$c = "downloadUrl"

	condition:
		($a and $c)
}
