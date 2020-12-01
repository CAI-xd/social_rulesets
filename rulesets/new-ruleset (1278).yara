/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TasconTT
    Rule name: New Ruleset
    Rule id: 1278
    Created at: 2016-03-14 13:15:52
    Updated at: 2016-03-14 13:18:17
    
    Rating: #0
    Total detections: 10988
*/

import "androguard"
import "file"
import "cuckoo"


rule sandrorat
{
	meta:
		description="This rule detects SandroRat samples"
		
	strings:
		$a="SandroRat"
		
	condition:
		$a
}
