/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mike321
    Rule name: test2
    Rule id: 6323
    Created at: 2020-01-27 23:58:59
    Updated at: 2020-01-28 00:00:35
    
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
		$a = {45 70 6F 6E 61 57 68 69 74 65 62 6F 78}

	condition:
		$a
		
}
