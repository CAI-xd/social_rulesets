/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mike321
    Rule name: New Ruleset
    Rule id: 6322
    Created at: 2020-01-27 23:58:02
    Updated at: 2020-01-27 23:58:33
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects some packer"

	strings:
		$a = {45 70 6F 6E 61 57 68 69 74 65 42 6F 78}

	condition:
		$a
		
}
