/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: El
    Rule name: New Ruleset
    Rule id: 6225
    Created at: 2019-12-17 09:31:29
    Updated at: 2019-12-17 09:33:15
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"

	strings:
		$a = {33 35 2e 31 39 38 2e 31 39 37 2e 31 31 39 0a}
		$b = {33 35 2e 31 39 38 2e 31 39 37 2e 31 31 39 3a 38 30 38 30 2f 61 64 73 73 65 72 76 65 72 2d 76 33 2f 63 6c 69 65 6e 74 5f 63 6f 6e 66 69 67}

	condition:
		$a or $b
}
